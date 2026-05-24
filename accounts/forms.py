from pathlib import Path

from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm

from .models import Document, User
from .services import scan_document_file


class RegisterIdentityForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "phone_number")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["first_name"].required = True
        self.fields["last_name"].required = True
        self.fields["email"].widget.attrs.update({
            "placeholder": "Enter your email address",
            "autocomplete": "email",
        })
        self.fields["phone_number"].required = False
        self.fields["phone_number"].widget.attrs.update({
            "placeholder": "Optional phone number",
            "autocomplete": "tel",
        })


class RegisterPasswordForm(UserCreationForm):
    class Meta:
        model = User
        fields = ()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["password1"].widget.attrs.update({
            "placeholder": "Create a strong password",
            "autocomplete": "new-password",
        })
        self.fields["password2"].widget.attrs.update({
            "placeholder": "Confirm your password",
            "autocomplete": "new-password",
        })


class RegisterSecurityForm(forms.ModelForm):
    security_answer = forms.CharField(widget=forms.PasswordInput(render_value=False))
    pin = forms.CharField(min_length=4, max_length=8, widget=forms.PasswordInput(render_value=False))
    captcha_checkbox = forms.BooleanField(
        required=True,
        label="I'm not a robot",
        widget=forms.CheckboxInput(attrs={
            'class': 'captcha-checkbox',
            'aria-label': "I'm not a robot CAPTCHA verification"
        })
    )

    class Meta:
        model = User
        fields = ("security_question",)

    def clean_pin(self):
        pin = self.cleaned_data["pin"]
        if not pin.isdigit() or not 4 <= len(pin) <= 8:
            raise forms.ValidationError("PIN must be 4 to 8 digits.")
        return pin


class SecurityQuestionSetupForm(forms.ModelForm):
    security_answer = forms.CharField(widget=forms.PasswordInput(render_value=False))

    class Meta:
        model = User
        fields = ("security_question",)


class PinSetupForm(forms.Form):
    pin = forms.CharField(min_length=4, max_length=8, widget=forms.PasswordInput(render_value=False))

    def clean_pin(self):
        pin = self.cleaned_data["pin"]
        if not pin.isdigit() or not 4 <= len(pin) <= 8:
            raise forms.ValidationError("PIN must be 4 to 8 digits.")
        return pin


class VoiceBaseForm(forms.Form):
    spoken_phrase = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={
            "placeholder": "Speak the challenge phrase, then confirm it here",
            "autocomplete": "off",
        }),
        help_text="Speak the phrase shown on screen in your normal voice.",
    )
    audio_file = forms.FileField(
        widget=forms.ClearableFileInput(attrs={
            "accept": ".wav,audio/wav",
        }),
        help_text="A short WAV recording captured from this device.",
    )

    def clean_spoken_phrase(self):
        phrase = " ".join(self.cleaned_data["spoken_phrase"].strip().split())
        word_count = len(phrase.split())
        if word_count < 3 or word_count > 8:
            raise forms.ValidationError("Use a phrase with 3 to 8 words.")
        return phrase

    def clean_audio_file(self):
        audio_file = self.cleaned_data["audio_file"]
        suffix = Path(audio_file.name or "").suffix.lower()
        if suffix not in {".wav", ".wave"}:
            raise forms.ValidationError("Please upload a WAV recording.")
        if audio_file.size > 5 * 1024 * 1024:
            raise forms.ValidationError("Voice recording is too large.")
        return audio_file


class VoiceSetupForm(VoiceBaseForm):
    pass


class VoiceVerificationForm(VoiceBaseForm):
    pass


class EmailAuthenticationForm(AuthenticationForm):
    username = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={
            'placeholder': 'Enter your email address',
            'autocomplete': 'email'
        })
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Enter your password'
        })
    )

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
    captcha_checkbox = forms.BooleanField(
        required=True,
        label="I'm not a robot",
        widget=forms.CheckboxInput(attrs={
            'class': 'captcha-checkbox',
            'aria-label': "I'm not a robot CAPTCHA verification"
        })
    )
    captcha_timestamp = forms.IntegerField(widget=forms.HiddenInput(), required=False)


class ImageVerificationForm(forms.Form):
    image_choices = forms.MultipleChoiceField(
        widget=forms.CheckboxSelectMultiple,
        label="Choose all matching images",
        required=True,
    )


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


class TextCaptchaForm(forms.Form):
    captcha_input = forms.CharField(
        label="Text Verification",
        max_length=6,
        widget=forms.TextInput(attrs={
            'placeholder': 'Enter characters',
            'autocomplete': 'off',
            'class': 'captcha-input-field'
        })
    )


class ProfileUpdateForm(forms.ModelForm):
    role_display = forms.CharField(label="Account Role", disabled=True, required=False)
    member_since = forms.CharField(label="Member Since", disabled=True, required=False)

    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "phone_number")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields["role_display"].initial = self.instance.get_role_display()
            self.fields["member_since"].initial = self.instance.date_joined.strftime("%B %Y")

        for field in self.fields.values():
            field.required = False

        self.fields["email"].disabled = True
        self.fields["first_name"].widget.attrs.update({"placeholder": "First name"})
        self.fields["last_name"].widget.attrs.update({"placeholder": "Last name"})
        self.fields["phone_number"].widget.attrs.update({"placeholder": "Phone number"})
        self.fields["email"].widget.attrs.update({"placeholder": "Email address"})


class ProfilePasswordForm(forms.Form):
    current_password = forms.CharField(widget=forms.PasswordInput(render_value=False, attrs={"placeholder": "Enter current password"}))
    new_password = forms.CharField(
        min_length=8,
        widget=forms.PasswordInput(render_value=False, attrs={"placeholder": "New password (min 8 chars)"}),
    )
    confirm_password = forms.CharField(widget=forms.PasswordInput(render_value=False, attrs={"placeholder": "Confirm new password"}))

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("new_password")
        p2 = cleaned.get("confirm_password")
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("New passwords do not match.")
        return cleaned


class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField(label="Email Address", widget=forms.EmailInput(attrs={
        'placeholder': 'Enter your registered email',
        'autocomplete': 'email'
    }))


class PasswordResetOTPForm(forms.Form):
    otp = forms.CharField(
        min_length=6,
        max_length=6,
        strip=True,
        label="OTP Code",
        widget=forms.TextInput(attrs={
            'placeholder': '000000',
            'autocomplete': 'off'
        })
    )


class SetPasswordForm(forms.Form):
    new_password = forms.CharField(
        min_length=8, # Ensure password meets minimum length requirement
        widget=forms.PasswordInput(render_value=False),
        label="New Password",
        help_text="Minimum 8 characters"
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(render_value=False),
        label="Confirm Password"
    )

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')

        if new_password and confirm_password:
            if new_password != confirm_password:
                raise forms.ValidationError("Passwords do not match.")
        return cleaned_data


class DocumentUploadForm(forms.ModelForm):
    """Accept one local document upload from an MFA-verified user."""

    class Meta:
        model = Document
        fields = ("file",)
        widgets = {
            "file": forms.ClearableFileInput(attrs={
                "class": "form-control",
            }),
        }

    def clean_file(self):
        uploaded_file = self.cleaned_data["file"]
        if uploaded_file.size > 10 * 1024 * 1024:
            raise forms.ValidationError("Document must be 10 MB or smaller.")

        is_clean, scan_message = scan_document_file(uploaded_file)
        if not is_clean:
            raise forms.ValidationError(scan_message)

        return uploaded_file
