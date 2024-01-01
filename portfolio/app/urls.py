from django.urls import path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from app import views
from django.conf import settings
from django.conf.urls.static import static

schema_view = get_schema_view(
   openapi.Info(
      title="PortfolioHub",
      default_version='v1',
      description="PortfolioHub is a versatile and user-friendly web application that empowers individuals to create and manage their professional portfolios effortlessly. With a sleek and intuitive interface, PortfolioHub provides features such as user registration, secure login, and personalized profile management. Users can showcase their skills and experiences through dynamic portfolios, categorized services, informative blogs, and brand collaborations. The project also includes functionalities like FAQ management, category organization, and media-rich content creation. PortfolioHub is a one-stop platform designed to elevate personal and professional online presence, making it an ideal choice for freelancers, entrepreneurs, and creative professionals.",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="pratappatilmh24@gmail.com"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
   path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
   path('RegisterUser/',views.RegisterUser.as_view()),
   path('VerifyEmail/',views.VerifyEmail.as_view()),
   path('Login/',views.Login.as_view()),
   path('ForgotPasswordView/',views.ForgotPasswordView.as_view()),
   path('ResetPasswordView/',views.ResetPasswordView.as_view()),
   path('ChangePasswordView/',views.ChangePasswordView.as_view()),
   path('ProfileData/',views.ProfileDataGet.as_view()),
   path('ProfileDataUpdate/<int:id>/',views.ProfileDataUpdate.as_view()),
   path('Logout/',views.Logout.as_view()),
# static contents
   path('StaticContentView_terms/',views.StaticContentView_terms.as_view()),
   path('StaticContentView_privacy/',views.StaticContentView_privacy.as_view()),
   path('AddFAQView/',views.AddFAQView.as_view()),
   path('GetAllFAQView/',views.GetAllFAQView.as_view()),
   path('getPerticularFAQ/<int:id>/',views.getPerticularFAQ.as_view()),
   path('FAQDelete/<int:id>/',views.FAQDelete.as_view()),
# pratap......
   path('Add_New_Service/',views.Add_New_Service.as_view(),name='Add_New_Service'),
   path('get_unique_service/',views.get_unique_service.as_view(),name='get_unique_service'),
   path('get_all_service/',views.get_all_service.as_view(),name='get_all_service'),
   path('get_perticular_service/<int:id>/',views.get_perticular_service.as_view(),name='get_perticular_service'),
   path('update_service/<int:id>/',views.update_service.as_view(),name='update_service'),
   path('delete_service/<int:id>/',views.delete_service.as_view(),name='delete_service'),
   path('Add_category/',views.Add_category.as_view(),name='Add_category'),
   path('get_all_category/',views.get_all_category.as_view(),name='get_all_category'),
   path('get_perticular_category/<int:id>/',views.get_perticular_category.as_view(),name='get_perticular_category'),
   path('get_searched_category/',views.get_searched_category.as_view(),name='get_searched_category'),
   path('update_category/<int:id>/',views.update_category.as_view(),name='update_category'),
   path('delete_category/<int:id>/',views.delete_category.as_view(),name='delete_category'),
   path('Add_New_Portfolio/',views.Add_New_Portfolio.as_view(),name='Add_New_Portfolio'),
   path('Get_All_Portfolio/',views.Get_All_Portfolio.as_view(),name='Get_All_Portfolio'),
   path('Get_Perticular_Portfolio/<int:id>/',views.Get_Perticular_Portfolio.as_view(),name='Get_Perticular_Portfolio'),
   path('GetUniquePortfolio/',views.GetUniquePortfolio.as_view(),name='GetUniquePortfolio'),
   path('update_Portfolio/<int:id>/',views.update_Portfolio.as_view(),name='update_Portfolio'),
   path('delete_portfolio/<int:id>/',views.delete_portfolio.as_view(),name='delete_portfolio'),
   path('get_portfolio_category/',views.get_portfolio_category.as_view(),name='get_portfolio_category'),
   path('GetAllBlogs/',views.GetAllBlogs.as_view(),name='GetAllBlogs'),
   path('Get_Perticular_blogs/<int:id>/',views.Get_Perticular_blogs.as_view(),name='Get_Perticular_blogs'),
   path('Get_unique_Blog/',views.Get_unique_Blog.as_view(),name='Get_unique_Blog'),
   path('CreateBlog/',views.CreateBlog.as_view(),name='CreateBlog'),
   path('UpdateBlog/<int:id>/',views.UpdateBlog.as_view(),name='UpdateBlog'),
   path('DeleteBlog/<int:id>/',views.DeleteBlog.as_view(),name='DeleteBlog'),
   path('get_blog_category/',views.get_blog_category().as_view(),name='get_blog_category'),
   path('GetAllBrands/',views.GetAllBrands.as_view(),name='GetAllBrands'),
   path('GetSearchedBrand/',views.GetSearchedBrand.as_view(),name='GetSearchedBrand'),
   path('Get_Perticular_brand/<int:id>/',views.Get_Perticular_brand.as_view(),name='Get_Perticular_brand'),
   path('CreateBrand/',views.CreateBrand.as_view(),name='CreateBrand'),
   path('UpdateBrand/<int:id>/',views.UpdateBrand.as_view(),name='UpdateBrand'),
   path('DeleteBrand/<int:id>/',views.DeleteBrand.as_view(),name='DeleteBrand'),
   path('Dashboard/',views.Dashboard.as_view(),name='Dashboard'),

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)