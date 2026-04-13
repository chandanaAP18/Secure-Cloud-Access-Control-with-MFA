from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm

from .models import User


class RegisterForm(UserCreationForm):
    phone_number = forms.CharField(max_length=20)
    security_answer = forms.CharField(widget=forms.PasswordInput(render_value=False))
    pin = forms.CharField(min_length=4, max_length=8, widget=forms.PasswordInput(render_value=False))

    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "phone_number", "security_question")

    def clean_pin(self):
        pin = self.cleaned_data["pin"]
        if not pin.isdigit() or not 4 <= len(pin) <= 8:
            raise forms.ValidationError("PIN must be 4 to 8 digits.")
        return pin

    def save(self, commit=True):
        user = super().save(commit=False)
        user.phone_number = self.cleaned_data["phone_number"]
        user.role = User.Role.USER
        user.security_question = self.cleaned_data["security_question"]
        user.set_security_answer(self.cleaned_data["security_answer"])
        user.set_pin(self.cleaned_data["pin"])
        if commit:
            user.save()
        return user


class EmailAuthenticationForm(AuthenticationForm):
    username = forms.EmailField(label="Email")

    def clean(self):
        email = self.cleaned_data.get("username")
        password = self.cleaned_data.get("password")
        if email and password:
            self.user_cache = authenticate(self.request, username=email, password=password)
            if self.user_cache is None:
                raise forms.ValidationError("Invalid email or password.")
            self.confirm_login_allowed(self.user_cache)
        return self.cleaned_data


class OTPVerificationForm(forms.Form):
    otp = forms.CharField(min_length=6, max_length=6, strip=True)


class CaptchaVerificationForm(forms.Form):
    captcha = forms.CharField(min_length=4, max_length=6, strip=True, label="Enter the CAPTCHA")


class ImageVerificationForm(forms.Form):
    image_choice = forms.ChoiceField(widget=forms.RadioSelect, label="Choose the matching image")


class FactorSelectionForm(forms.Form):
    factor = forms.ChoiceField(
        choices=(
            ("EMAIL", "Email OTP"),
            ("PHONE", "Phone OTP"),
            ("PIN", "PIN"),
            ("QUESTION", "Security Question"),
        ),
        widget=forms.RadioSelect,
    )


class PinVerificationForm(forms.Form):
    pin = forms.CharField(min_length=4, max_length=8, widget=forms.PasswordInput(render_value=False))


class SecurityQuestionForm(forms.Form):
    answer = forms.CharField(widget=forms.PasswordInput(render_value=False))


class TOTPVerificationForm(forms.Form):
    otp = forms.CharField(min_length=6, max_length=6, strip=True)
