import random
import string


def generate_random_honeytoken_name() -> str:
    """Generate a honeytoken name based on a random string of eight alphanumeric characters"""
    letters_and_digits = string.ascii_letters + string.digits
    random_str = "".join(random.choice(letters_and_digits) for i in range(8))
    return f"ggshield-{random_str}"
