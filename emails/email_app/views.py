from django.shortcuts import render, redirect  # Removed duplicate import
from django.contrib.auth.models import User
from django.contrib.auth import login,authenticate,logout
from django.contrib.auth import authenticate,login as auth_login
from django.conf import settings
from django.core.mail import send_mail
from django.contrib import messages
import random

def signup(request):
    if request.method == "POST":  # Fixed syntax error
        username = request.POST["username"]  # Fixed syntax error
        email = request.POST["email"]  # Fixed syntax error
        password = request.POST["password"] 
        #checking username already exist
        if User.objects.filter(username=username).exists():
            return render(request, "signup.html", {"error": "Username already taken. Please choose a different one."})

        # Corrected the order and fixed syntax error
        user = User.objects.create_user(username=username, password=password, email=email)  # Fixed indentation
        login(request, user)  # Fixed syntax error
        
    #otp generation
        otp = random.randint(100000,999999)
        request.session['otp'] = otp  # Store OTP in session

        subject = 'Welcome to my World'  # Fixed syntax error
        message = f'Hi {user.username}, thank you for registering in my app , here is one time password :{otp}.'  # Fixed syntax error and typo
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [user.email,]
        send_mail(subject, message, email_from, recipient_list)
        print("success")
        return redirect("/verify_otp/")
    return render(request, "signup.html") # Fixed indentation

def dashboard_view(request):
    return render(request,"dashboard.html")

def verify_otp(request):
    if request.method == "POST":
        user_otp = request.POST.get("otp")
        if 'otp' in request.session:
            otp = request.session['otp']
            if str(otp) == user_otp:
                del request.session['otp']  # Remove OTP from session after successful verification
                return redirect("/dashboard/")
            else:
                return render(request, "verify_otp.html", {"error": "Invalid OTP. Please try again."})
    return render(request, "verify_otp.html")


from django.core.mail import send_mail
from django.contrib.auth import authenticate, login as auth_login
import random

def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # Generate OTP
            otp = random.randint(100000, 999999)
            request.session['otp'] = otp  # Store OTP in session for verification
            request.session['username'] = username  # Temporarily store username in session

            # Send OTP via email
            subject = 'Your OTP for login'
            message = f'Your OTP for login is {otp}.'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [user.email]
            send_mail(subject, message, email_from, recipient_list)

            return redirect('/verify_otp/')  # Redirect to OTP verification page
        else:
            # Handle login failure
            messages.error(request, "Invalid username or password. If you don't have an account, please sign up.")
    return render(request, "login.html")