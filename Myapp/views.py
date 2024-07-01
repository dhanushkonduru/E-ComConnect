from rest_framework import viewsets, generics, status, permissions
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from .models import Task, User, Category, Product, Cart, CartItem, Order, Wishlist, Review, Product, CartItem
from .serializers import UserSerializer, TaskSerializer, RegisterSerializer, LoginSerializer, CategorySerializer, \
    ProductSerializer, CartSerializer, CartItemSerializer, OrderSerializer, WishlistSerializer, ReviewSerializer
from rest_framework.exceptions import ValidationError
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .utils import generate_otp, send_otp_via_sms, generate_access_token
from rest_framework.views import APIView
import stripe
import logging

stripe.api_key = 'your_stripe_secret_key'


class UserList(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class TaskList(generics.ListCreateAPIView):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer


class TaskDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        refresh_token = request.data["refresh_token"]
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response(status=status.HTTP_205_RESET_CONTENT)
    except Exception as e:
        return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def login(request):
    try:
        phone_number = request.data["phone_number"]
        country_code = request.data["country_code"]
        otp = request.data["otp"]

        user = User.objects.get(phone_number=phone_number, country_code=country_code)

        if user.otp != otp or timezone.now() > user.otp_created_at + timezone.timedelta(minutes=10):
            raise ValidationError("Invalid or expired OTP")

        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
    except ValidationError as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'error': 'Something went wrong'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TaskViewSet(viewsets.ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        user_serializer = self.get_serializer(data=request.data)
        user_serializer.is_valid(raise_exception=True)
        user = user_serializer.save()

        tasks_data = request.data.get('tasks', [])
        for task_data in tasks_data:
            task_data['user'] = user.id
            task_serializer = TaskSerializer(data=task_data)
            task_serializer.is_valid(raise_exception=True)
            task_serializer.save()

        headers = self.get_success_headers(user_serializer.data)
        return Response(user_serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        user_serializer = self.get_serializer(instance, data=request.data, partial=partial)
        user_serializer.is_valid(raise_exception=True)
        user = user_serializer.save()

        tasks_data = request.data.get('tasks', [])
        task_ids = [task['id'] for task in tasks_data if 'id' in task]

        for task in user.tasks.all():
            if task.id not in task_ids:
                task.delete()

        for task_data in tasks_data:
            task_id = task_data.get('id')
            if task_id:
                task_instance = Task.objects.get(id=task_id, user=user)
                task_serializer = TaskSerializer(task_instance, data=task_data, partial=partial)
            else:
                task_data['user'] = user.id
                task_serializer = TaskSerializer(data=task_data)
            task_serializer.is_valid(raise_exception=True)
            task_serializer.save()

        return Response(user_serializer.data)


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()

            otp = generate_otp()
            user.otp = otp
            user.otp_created_at = timezone.now()
            user.save()

            phone_number = f"{user.country_code}{user.phone_number}"
            send_otp_via_sms(phone_number, otp)

            return Response({
                'message': 'User registered successfully. OTP sent to phone number.'
            }, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': 'Something went wrong'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@login_required
def profile(request):
    return render(request, 'profile.html')


@api_view(['POST'])
def register_user(request):
    try:
        phone_number = request.data.get('phone_number')
        country_code = request.data.get('country_code')

        if not phone_number or not country_code:
            return Response({'error': 'Phone number and country code are required'}, status=status.HTTP_400_BAD_REQUEST)

        otp = generate_otp()

        user, created = User.objects.update_or_create(
            phone_number=phone_number,
            defaults={
                'country_code': country_code,
                'otp': otp,
                'otp_created_at': timezone.now()
            }
        )

        phone_with_code = f"{country_code}{phone_number}"
        if send_otp_via_sms(phone_with_code, otp):
            return Response({'message': 'OTP sent successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Failed to send OTP via SMS.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        return Response({'error': f'Something went wrong: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def generate_otp_and_send_sms(request):
    try:
        phone_number = request.data["phone_number"]
        country_code = request.data["country_code"]

        user = User.objects.get(phone_number=phone_number, country_code=country_code)

        otp = generate_otp()
        user.otp = otp
        user.otp_created_at = timezone.now()
        user.save()

        phone_with_code = f"{country_code}{phone_number}"
        send_otp_via_sms(phone_with_code, otp)

        return JsonResponse({'message': 'OTP generated and sent successfully.'}, status=200)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User does not exist.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.validated_data['phone']
        country_code = serializer.validated_data['country_code']
        otp = serializer.validated_data['otp']

        try:
            user = User.objects.get(phone_number=phone, country_code=country_code)
            if user.otp == otp and user.otp_created_at > timezone.now() - timezone.timedelta(minutes=10):
                access_token = generate_access_token(user)
                return Response({'access_token': access_token}, status=status.HTTP_201_CREATED)
            else:
                return Response({'detail': 'Invalid OTP or OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [AllowAny]


class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [AllowAny]


class CartViewSet(viewsets.ModelViewSet):
    queryset = Cart.objects.all()
    serializer_class = CartSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Cart.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        cart, created = Cart.objects.get_or_create(user=request.user)
        return Response(CartSerializer(cart).data)


class CartItemViewSet(viewsets.ModelViewSet):
    queryset = CartItem.objects.all()
    serializer_class = CartItemSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        cart = get_object_or_404(Cart, user=self.request.user)
        return CartItem.objects.filter(cart=cart)

    def create(self, request, *args, **kwargs):
        cart = get_object_or_404(Cart, user=request.user)
        product = get_object_or_404(Product, id=request.data['product_id'])
        quantity = request.data['quantity']

        cart_item, created = CartItem.objects.get_or_create(cart=cart, product=product)
        if not created:
            cart_item.quantity += int(quantity)
        else:
            cart_item.quantity = quantity
        cart_item.save()

        return Response(CartItemSerializer(cart_item).data, status=status.HTTP_201_CREATED)


logger = logging.getLogger(__name__)


class WishlistViewSet(viewsets.ModelViewSet):
    queryset = Wishlist.objects.all()
    serializer_class = WishlistSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        def get_queryset(self):
            user = self.request.user
            logger.debug(f"User: {user}, Type: {type(user)}")
            if isinstance(user, User):
                return Wishlist.objects.filter(user=user)
            else:
                raise ValueError("Authenticated user is not a valid User instance")

    def create(self, request, *args, **kwargs):
        user = request.user
        product = get_object_or_404(Product, id=request.data['product_id'])
        wishlist_item, created = Wishlist.objects.get_or_create(user=user, product=product)
        if created:
            return Response(WishlistSerializer(wishlist_item).data, status=status.HTTP_201_CREATED)
        else:
            return Response({"detail": "Product already in wishlist"}, status=status.HTTP_400_BAD_REQUEST)


class ReviewViewSet(viewsets.ModelViewSet):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        product = self.request.query_params.get('product', None)
        if product is not None:
            return Review.objects.filter(product_id=product)
        return super().get_queryset()

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        cart = get_object_or_404(Cart, user=request.user)
        order = Order.objects.create(user=request.user, total_price=0)

        total_price = 0
        for item in cart.items.all():
            total_price += item.product.price * item.quantity
            item.delete()

        order.total_price = total_price
        order.save()

        try:
            payment_intent = stripe.PaymentIntent.create(
                amount=int(total_price * 100),
                currency='usd',
                payment_method_types=['card'],
            )
            order.payment_id = payment_intent.id
            order.save()
            return Response({'payment_intent': payment_intent.client_secret, 'order_id': order.id})
        except Exception as e:
            order.delete()
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_payment_intent(request):
    order = get_object_or_404(Order, id=request.data['order_id'], user=request.user)
    intent = stripe.PaymentIntent.create(
        amount=int(order.total_price * 100),  # amount in cents
        currency='usd',
        metadata={'integration_check': 'accept_a_payment'}
    )
    return Response({
        'client_secret': intent['client_secret']
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_to_cart(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    cart, created = Cart.objects.get_or_create(user=request.user)
    cart_item, created = CartItem.objects.get_or_create(cart=cart, product=product)

    if not created:
        cart_item.quantity += 1
        cart_item.save()

    return Response(CartItemSerializer(cart_item).data, status=status.HTTP_201_CREATED)


def cart_view(request):
    cart_items = CartItem.objects.all()
    total_price = sum(item.get_total_price() for item in cart_items)
    return render(request, 'cart.html', {'cart_items': cart_items, 'total_price': total_price})