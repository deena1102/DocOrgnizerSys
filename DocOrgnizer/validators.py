from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
import string

class IsEntireAlphaPasswordValidator:
    def validate(self, password, user=None):
        if password.isalpha():
            raise ValidationError(
                _("Password cannot consist entirely of alphabetic characters."),
                code='password_entire_alpha',
            )

    def get_help_text(self):
        return _("Password cannot consist entirely of alphabetic characters.")


class HasUpperCasePasswordValidator:
    def validate(self, password, user=None):
        if not any(char.isupper() for char in password):
            raise ValidationError(
                _("Password must contain at least one uppercase letter."),
                code='password_no_upper',
            )

    def get_help_text(self):
        return _("Password must contain at least one uppercase letter.")

class HasLowerCasePasswordValidator:
    def validate(self, password, user=None):
        if not any(char.islower() for char in password):
            raise ValidationError(
                _("Password must contain at least one lowercase letter."),
                code='password_no_lower',
            )

    def get_help_text(self):
        return _("Password must contain at least one lowercase letter.")
    
class HasNumberPasswordValidator:
    def validate(self, password, user=None):
        if not any(char.isdigit() for char in password):
            raise ValidationError(
                _("Password must contain at least one numeric character."),
                code='password_no_digit',
            )

    def get_help_text(self):
        return _("Password must contain at least one numeric character.")
    
class HasSpecialCharacterPasswordValidator:
    def validate(self, password, user=None):
        special_characters = set(string.punctuation)
        if not any(char in special_characters for char in password):
            raise ValidationError(
                _("Password must contain at least one special character."),
                code='password_no_special_character',
            )

    def get_help_text(self):
        return _("Password must contain at least one special character.")