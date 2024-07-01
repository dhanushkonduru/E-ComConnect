from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from Myapp.views import UserViewSet, TaskViewSet, RegisterView, profile, UserList, TaskList, TaskDetail, login, generate_otp_and_send_sms, CategoryViewSet, ProductViewSet, CartViewSet, CartItemViewSet, OrderViewSet, WishlistViewSet, ReviewViewSet, add_to_cart, cart_view

router = routers.DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'tasks', TaskViewSet)
router.register(r'categories', CategoryViewSet)
router.register(r'products', ProductViewSet)
router.register(r'cart', CartViewSet, basename='cart')
router.register(r'cart-items', CartItemViewSet, basename='cartitem')
router.register(r'orders', OrderViewSet, basename='order')
router.register(r'wishlists', WishlistViewSet, basename='wishlist')
router.register(r'reviews', ReviewViewSet)


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/login/', login, name='login'),
    path('api/users/', UserList.as_view(), name='user-list'),
    path('api/tasks/', TaskList.as_view(), name='task-list'),
    path('api/tasks/<int:pk>/', TaskDetail.as_view(), name='task-detail'),
    path('api/generate-otp/', generate_otp_and_send_sms, name='generate_otp'),
    path('api/users/generate-otp/', generate_otp_and_send_sms, name='generate_user_otp'),
    path('accounts/profile/', profile, name='profile'),
    path('cart/', cart_view, name='cart'),
    path('add_to_cart/<int:product_id>/', add_to_cart, name='add_to_cart'),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
]
