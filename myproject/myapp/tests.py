from django.test import TestCase
import random,string

# Create your tests here.
def code():
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(6))

print(code())
