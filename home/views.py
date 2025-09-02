# from django.shortcuts import render, redirect
# from datetime import datetime
# from home.models import Contact, UserProfile, EncryptedPost
# from django.contrib import messages
# from django.contrib.auth.models import User
# from django.contrib.auth import authenticate, login, logout
# from django.contrib.auth.decorators import login_required
# from django.contrib.auth.hashers import make_password, check_password
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# from base64 import b64encode, b64decode
# from django.conf import settings

# from .key_manager import get_encryption_key
# import base64

# # Central AES key
# ENCRYPTION_KEY = get_encryption_key()


# # Helper to check if string is base64
# def is_base64(s):
#     try:
#         if isinstance(s, str):
#             s_bytes = s.encode()
#         else:
#             s_bytes = s
#         return base64.b64encode(base64.b64decode(s_bytes)) == s_bytes
#     except Exception:
#         return False


# # Encryption function
# def encrypt_value(plaintext):
#     if isinstance(plaintext, str):
#         data = plaintext.encode()
#     else:
#         data = plaintext  # For binary data
#     cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
#     padded_data = pad(data, AES.block_size)
#     encrypted_bytes = cipher.encrypt(padded_data)
#     return b64encode(encrypted_bytes).decode('utf-8')


# # Decryption function
# def decrypt_value(encrypted_value):
#     if not encrypted_value:
#         return ''
#     cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
#     try:
#         encrypted_bytes = b64decode(encrypted_value.encode('utf-8'))
#         decrypted_padded_bytes = cipher.decrypt(encrypted_bytes)
#         decrypted_value = unpad(decrypted_padded_bytes, AES.block_size).decode('utf-8')
#         return decrypted_value
#     except Exception:
#         # In case of error (e.g., superuser plain text), return original
#         return encrypted_value


# # Separate credential check function
# def check_credentials(input_username, input_password):
#     try:
#         user = User.objects.get(username=input_username)
#         if check_password(input_password, user.password):
#             return user
#     except User.DoesNotExist:
#         return None
#     return None


# # Views

# def index(request):
#     if request.user.is_anonymous:
#         return redirect('/login')
#     context = {'variable1': 'this is sent', 'variable2': 'another variable'}
#     return render(request, 'index.html', context)


# def signup(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         username = request.POST.get('username')
#         first_name = request.POST.get('firstname')
#         last_name = request.POST.get('lastname')
#         password = request.POST.get('password')
#         profile_picture = request.FILES.get('profile_picture')  # optional

#         # Encrypt sensitive info
#         encrypted_email = encrypt_value(email)
#         encrypted_first_name = encrypt_value(first_name)
#         encrypted_last_name = encrypt_value(last_name)

#         try:
#             user = User(
#                 username=username,
#                 email=encrypted_email,
#                 first_name=encrypted_first_name,
#                 last_name=encrypted_last_name,
#                 password=make_password(password)
#             )
#             user.save()

#             # Encrypt and store profile picture
#             if profile_picture:
#                 img_bytes = profile_picture.read()
#                 encrypted_image = encrypt_value(img_bytes.hex())
#                 UserProfile.objects.create(
#                     user=user,
#                     encrypted_profile_picture=encrypted_image.encode()
#                 )

#             messages.success(request, 'User registered successfully.')
#             return redirect('login')
#         except Exception as e:
#             messages.error(request, str(e))
#             return render(request, 'signup.html')

#     return render(request, 'signup.html')


# def loginUser(request):
#     if request.method == "POST":
#         username = request.POST.get("username")
#         password = request.POST.get("password")

#         user = check_credentials(username, password)
#         if user:
#             login(request, user)
#             return redirect('/')
#         else:
#             messages.error(request, "Invalid username or password")
#             return render(request, "login.html")

#     return render(request, "login.html")


# def logoutUser(request):
#     logout(request)
#     return redirect("/login")


# @login_required
# def profile(request):
#     user = request.user

#     # Decrypt user fields if base64-encoded
#     decrypted_email = decrypt_value(user.email) if user.email and is_base64(user.email) else user.email
#     decrypted_first_name = decrypt_value(user.first_name) if user.first_name and is_base64(user.first_name) else user.first_name
#     decrypted_last_name = decrypt_value(user.last_name) if user.last_name and is_base64(user.last_name) else user.last_name

#     # Profile picture handling
#     profile_picture = None
#     if hasattr(user, 'profile') and user.profile.encrypted_profile_picture:
#         encrypted_pic = user.profile.encrypted_profile_picture
#         if encrypted_pic and encrypted_pic.strip():
#             try:
#                 decrypted_image_hex = decrypt_value(encrypted_pic.decode('utf-8'))
#                 if decrypted_image_hex:
#                     profile_picture = bytes.fromhex(decrypted_image_hex)
#             except Exception:
#                 profile_picture = None

#     context = {
#         'email': decrypted_email,
#         'first_name': decrypted_first_name,
#         'last_name': decrypted_last_name,
#         'profile_picture': profile_picture
#     }

#     return render(request, 'profile.html', context)


# def about(request):
#     return render(request, 'about.html')


# def operators(request):
#     return render(request, 'operators.html')


# def contact(request):
#     if request.method == 'POST':
#         name = request.POST.get('name')
#         email = request.POST.get('email')
#         phone = request.POST.get('phone')
#         desc = request.POST.get('desc')
#         contact = Contact(name=name, email=email, phone=phone, desc=desc, date=datetime.today())
#         contact.save()
#         messages.success(request, "You have successfully submitted the form.")

#     return render(request, 'contact.html')


# @login_required
# def create_encrypted_post(request):
#     if request.method == 'POST':
#         title = request.POST.get('title')
#         content = request.POST.get('content')

#         encrypted_title = encrypt_value(title)
#         encrypted_content = encrypt_value(content)

#         # Save in database
#         EncryptedPost.objects.create(
#             user=request.user,
#             encrypted_title=encrypted_title,
#             encrypted_content=encrypted_content
#         )

#         messages.success(request, "Your post has been submitted successfully.")
#         return redirect('view_encrypted_post')

#     return render(request, 'create_encrypted_post.html')


# @login_required
# def view_encrypted_post(request):
#     posts = EncryptedPost.objects.filter(user=request.user).order_by('-created_at')
#     decrypted_posts = []

#     for p in posts:
#         decrypted_posts.append({
#             'title': decrypt_value(p.encrypted_title),
#             'content': decrypt_value(p.encrypted_content),
#             'created_at': p.created_at  # updated field name
#         })

#     context = {'posts': decrypted_posts}
#     return render(request, 'view_encrypted_post.html', context)









# from django.shortcuts import render, redirect
# from datetime import datetime
# from home.models import Contact, UserProfile, EncryptedPost
# from django.contrib import messages
# from django.contrib.auth.models import User
# from django.contrib.auth import authenticate, login, logout
# from django.contrib.auth.decorators import login_required
# from django.contrib.auth.hashers import make_password, check_password
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# from Crypto.Hash import HMAC, SHA256
# from base64 import b64encode, b64decode
# from django.conf import settings

# from .key_manager import get_encryption_key
# import base64

# # Central AES key
# ENCRYPTION_KEY = get_encryption_key()


# # Helper to check if string is base64
# def is_base64(s):
#     try:
#         if isinstance(s, str):
#             s_bytes = s.encode()
#         else:
#             s_bytes = s
#         return base64.b64encode(base64.b64decode(s_bytes)) == s_bytes
#     except Exception:
#         return False


# # AES Encryption function
# def encrypt_value(plaintext):
#     if isinstance(plaintext, str):
#         data = plaintext.encode()
#     else:
#         data = plaintext  # For binary data
#     cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
#     padded_data = pad(data, AES.block_size)
#     encrypted_bytes = cipher.encrypt(padded_data)
#     return b64encode(encrypted_bytes).decode('utf-8')


# # AES Decryption function
# def decrypt_value(encrypted_value):
#     if not encrypted_value:
#         return ''
#     cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
#     try:
#         encrypted_bytes = b64decode(encrypted_value.encode('utf-8'))
#         decrypted_padded_bytes = cipher.decrypt(encrypted_bytes)
#         decrypted_value = unpad(decrypted_padded_bytes, AES.block_size).decode('utf-8')
#         return decrypted_value
#     except Exception:
#         # In case of error (e.g., superuser plain text), return original
#         return encrypted_value


# # Compute HMAC for integrity
# def compute_mac(data):
#     if isinstance(data, str):
#         data = data.encode()
#     h = HMAC.new(ENCRYPTION_KEY, digestmod=SHA256)
#     h.update(data)
#     return h.hexdigest()


# # Verify HMAC
# def verify_mac(data, mac_to_verify):
#     if isinstance(data, str):
#         data = data.encode()
#     h = HMAC.new(ENCRYPTION_KEY, digestmod=SHA256)
#     h.update(data)
#     try:
#         h.hexverify(mac_to_verify)
#         return True
#     except ValueError:
#         return False


# # Separate credential check function
# def check_credentials(input_username, input_password):
#     try:
#         user = User.objects.get(username=input_username)
#         if check_password(input_password, user.password):
#             return user
#     except User.DoesNotExist:
#         return None
#     return None


# # Views

# def index(request):
#     if request.user.is_anonymous:
#         return redirect('/login')
#     context = {'variable1': 'this is sent', 'variable2': 'another variable'}
#     return render(request, 'index.html', context)


# def signup(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         username = request.POST.get('username')
#         first_name = request.POST.get('firstname')
#         last_name = request.POST.get('lastname')
#         password = request.POST.get('password')
#         profile_picture = request.FILES.get('profile_picture')  # optional

#         # Encrypt sensitive info
#         encrypted_email = encrypt_value(email)
#         encrypted_first_name = encrypt_value(first_name)
#         encrypted_last_name = encrypt_value(last_name)

#         try:
#             user = User(
#                 username=username,
#                 email=encrypted_email,
#                 first_name=encrypted_first_name,
#                 last_name=encrypted_last_name,
#                 password=make_password(password)
#             )
#             user.save()

#             # Encrypt and store profile picture
#             if profile_picture:
#                 img_bytes = profile_picture.read()
#                 encrypted_image = encrypt_value(img_bytes.hex())
#                 UserProfile.objects.create(
#                     user=user,
#                     encrypted_profile_picture=encrypted_image.encode()
#                 )

#             messages.success(request, 'User registered successfully.')
#             return redirect('login')
#         except Exception as e:
#             messages.error(request, str(e))
#             return render(request, 'signup.html')

#     return render(request, 'signup.html')


# def loginUser(request):
#     if request.method == "POST":
#         username = request.POST.get("username")
#         password = request.POST.get("password")

#         user = check_credentials(username, password)
#         if user:
#             login(request, user)
#             return redirect('/')
#         else:
#             messages.error(request, "Invalid username or password")
#             return render(request, "login.html")

#     return render(request, "login.html")


# def logoutUser(request):
#     logout(request)
#     return redirect("/login")


# @login_required
# def profile(request):
#     user = request.user

#     # Decrypt user fields if base64-encoded
#     decrypted_email = decrypt_value(user.email) if user.email and is_base64(user.email) else user.email
#     decrypted_first_name = decrypt_value(user.first_name) if user.first_name and is_base64(user.first_name) else user.first_name
#     decrypted_last_name = decrypt_value(user.last_name) if user.last_name and is_base64(user.last_name) else user.last_name

#     # Profile picture handling
#     profile_picture = None
#     if hasattr(user, 'profile') and user.profile.encrypted_profile_picture:
#         encrypted_pic = user.profile.encrypted_profile_picture
#         if encrypted_pic and encrypted_pic.strip():
#             try:
#                 decrypted_image_hex = decrypt_value(encrypted_pic.decode('utf-8'))
#                 if decrypted_image_hex:
#                     profile_picture = bytes.fromhex(decrypted_image_hex)
#             except Exception:
#                 profile_picture = None

#     context = {
#         'email': decrypted_email,
#         'first_name': decrypted_first_name,
#         'last_name': decrypted_last_name,
#         'profile_picture': profile_picture
#     }

#     return render(request, 'profile.html', context)


# def about(request):
#     return render(request, 'about.html')


# def operators(request):
#     return render(request, 'operators.html')


# def contact(request):
#     if request.method == 'POST':
#         name = request.POST.get('name')
#         email = request.POST.get('email')
#         phone = request.POST.get('phone')
#         desc = request.POST.get('desc')
#         contact = Contact(name=name, email=email, phone=phone, desc=desc, date=datetime.today())
#         contact.save()
#         messages.success(request, "You have successfully submitted the form.")

#     return render(request, 'contact.html')


# @login_required
# def create_encrypted_post(request):
#     if request.method == 'POST':
#         title = request.POST.get('title')
#         content = request.POST.get('content')

#         encrypted_title = encrypt_value(title)
#         encrypted_content = encrypt_value(content)

#         # Compute MAC for integrity
#         title_mac = compute_mac(title)
#         content_mac = compute_mac(content)

#         # Save in database
#         EncryptedPost.objects.create(
#             user=request.user,
#             encrypted_title=encrypted_title,
#             encrypted_content=encrypted_content,
#             title_mac=title_mac,
#             content_mac=content_mac
#         )

#         messages.success(request, "Your post has been submitted successfully.")
#         return redirect('view_encrypted_post')

#     return render(request, 'create_encrypted_post.html')


# @login_required
# def view_encrypted_post(request):
#     posts = EncryptedPost.objects.filter(user=request.user).order_by('-created_at')
#     decrypted_posts = []

#     for p in posts:
#         decrypted_title = decrypt_value(p.encrypted_title)
#         decrypted_content = decrypt_value(p.encrypted_content)
#         # Verify integrity
#         title_valid = verify_mac(decrypted_title, p.title_mac)
#         content_valid = verify_mac(decrypted_content, p.content_mac)

#         decrypted_posts.append({
#             'title': decrypted_title,
#             'content': decrypted_content,
#             'created_at': p.created_at,
#             'title_valid': title_valid,
#             'content_valid': content_valid
#         })

#     context = {'posts': decrypted_posts}
#     return render(request, 'view_encrypted_post.html', context)








from django.shortcuts import render, redirect
from datetime import datetime
from home.models import Contact, UserProfile, EncryptedPost
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password, check_password
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
from base64 import b64encode, b64decode
from django.conf import settings

from .key_manager import get_encryption_key
import base64

# Central AES key
ENCRYPTION_KEY = get_encryption_key()


# Helper to check if string is base64
def is_base64(s):
    try:
        if isinstance(s, str):
            s_bytes = s.encode()
        else:
            s_bytes = s
        return base64.b64encode(base64.b64decode(s_bytes)) == s_bytes
    except Exception:
        return False


# AES Encryption function
def encrypt_value(plaintext):
    if isinstance(plaintext, str):
        data = plaintext.encode()
    else:
        data = plaintext  # For binary data
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)
    return b64encode(encrypted_bytes).decode('utf-8')


# AES Decryption function
def decrypt_value(encrypted_value):
    if not encrypted_value:
        return ''
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
    try:
        encrypted_bytes = b64decode(encrypted_value.encode('utf-8'))
        decrypted_padded_bytes = cipher.decrypt(encrypted_bytes)
        decrypted_value = unpad(decrypted_padded_bytes, AES.block_size).decode('utf-8')
        return decrypted_value
    except Exception:
        # In case of error (e.g., superuser plain text), return original
        return encrypted_value


# Compute HMAC for integrity
def compute_mac(data):
    if isinstance(data, str):
        data = data.encode()
    h = HMAC.new(ENCRYPTION_KEY, digestmod=SHA256)
    h.update(data)
    return h.hexdigest()


# Verify HMAC
def verify_mac(data, mac_to_verify):
    if isinstance(data, str):
        data = data.encode()
    h = HMAC.new(ENCRYPTION_KEY, digestmod=SHA256)
    h.update(data)
    try:
        h.hexverify(mac_to_verify)
        return True
    except ValueError:
        return False


# Separate credential check function
def check_credentials(input_username, input_password):
    try:
        user = User.objects.get(username=input_username)
        if check_password(input_password, user.password):
            return user
    except User.DoesNotExist:
        return None
    return None


# Views

def index(request):
    if request.user.is_anonymous:
        return redirect('/login')
    context = {'variable1': 'this is sent', 'variable2': 'another variable'}
    return render(request, 'index.html', context)


def signup(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        username = request.POST.get('username')
        first_name = request.POST.get('firstname')
        last_name = request.POST.get('lastname')
        password = request.POST.get('password')
        profile_picture = request.FILES.get('profile_picture')  # optional

        # Encrypt sensitive info
        encrypted_email = encrypt_value(email)
        encrypted_first_name = encrypt_value(first_name)
        encrypted_last_name = encrypt_value(last_name)

        try:
            user = User(
                username=username,
                email=encrypted_email,
                first_name=encrypted_first_name,
                last_name=encrypted_last_name,
                password=make_password(password)
            )
            user.save()

            # Compute MAC for profile integrity
            email_mac = compute_mac(email)
            first_name_mac = compute_mac(first_name)
            last_name_mac = compute_mac(last_name)

            # Encrypt and store profile picture
            encrypted_image = None
            if profile_picture:
                img_bytes = profile_picture.read()
                encrypted_image = encrypt_value(img_bytes.hex())

            # Create UserProfile with MACs
            UserProfile.objects.create(
                user=user,
                encrypted_profile_picture=encrypted_image.encode() if encrypted_image else None,
                email_mac=email_mac,
                first_name_mac=first_name_mac,
                last_name_mac=last_name_mac
            )

            messages.success(request, 'User registered successfully.')
            return redirect('login')
        except Exception as e:
            messages.error(request, str(e))
            return render(request, 'signup.html')

    return render(request, 'signup.html')


def loginUser(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = check_credentials(username, password)
        if user:
            login(request, user)
            return redirect('/')
        else:
            messages.error(request, "Invalid username or password")
            return render(request, "login.html")

    return render(request, "login.html")


def logoutUser(request):
    logout(request)
    return redirect("/login")


@login_required
def profile(request):
    user = request.user

    # Decrypt user fields if base64-encoded
    decrypted_email = decrypt_value(user.email) if user.email and is_base64(user.email) else user.email
    decrypted_first_name = decrypt_value(user.first_name) if user.first_name and is_base64(user.first_name) else user.first_name
    decrypted_last_name = decrypt_value(user.last_name) if user.last_name and is_base64(user.last_name) else user.last_name

    # Integrity check for profile fields
    email_valid = first_name_valid = last_name_valid = False
    if hasattr(user, 'profile'):
        profile = user.profile
        email_valid = verify_mac(decrypted_email, profile.email_mac) if profile.email_mac else False
        first_name_valid = verify_mac(decrypted_first_name, profile.first_name_mac) if profile.first_name_mac else False
        last_name_valid = verify_mac(decrypted_last_name, profile.last_name_mac) if profile.last_name_mac else False

    # Profile picture handling
    profile_picture = None
    if hasattr(user, 'profile') and user.profile.encrypted_profile_picture:
        encrypted_pic = user.profile.encrypted_profile_picture
        if encrypted_pic and encrypted_pic.strip():
            try:
                decrypted_image_hex = decrypt_value(encrypted_pic.decode('utf-8'))
                if decrypted_image_hex:
                    profile_picture = bytes.fromhex(decrypted_image_hex)
            except Exception:
                profile_picture = None

    context = {
        'email': decrypted_email,
        'first_name': decrypted_first_name,
        'last_name': decrypted_last_name,
        'profile_picture': profile_picture,
        'email_valid': email_valid,
        'first_name_valid': first_name_valid,
        'last_name_valid': last_name_valid
    }

    return render(request, 'profile.html', context)


def about(request):
    return render(request, 'about.html')


def operators(request):
    return render(request, 'operators.html')


def contact(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        desc = request.POST.get('desc')
        contact = Contact(name=name, email=email, phone=phone, desc=desc, date=datetime.today())
        contact.save()
        messages.success(request, "You have successfully submitted the form.")

    return render(request, 'contact.html')


@login_required
def create_encrypted_post(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        content = request.POST.get('content')

        encrypted_title = encrypt_value(title)
        encrypted_content = encrypt_value(content)

        # Compute MAC for integrity
        title_mac = compute_mac(title)
        content_mac = compute_mac(content)

        # Save in database
        EncryptedPost.objects.create(
            user=request.user,
            encrypted_title=encrypted_title,
            encrypted_content=encrypted_content,
            title_mac=title_mac,
            content_mac=content_mac
        )

        messages.success(request, "Your post has been submitted successfully.")
        return redirect('view_encrypted_post')

    return render(request, 'create_encrypted_post.html')


@login_required
def view_encrypted_post(request):
    posts = EncryptedPost.objects.filter(user=request.user).order_by('-created_at')
    decrypted_posts = []

    for p in posts:
        decrypted_title = decrypt_value(p.encrypted_title)
        decrypted_content = decrypt_value(p.encrypted_content)
        # Verify integrity
        title_valid = verify_mac(decrypted_title, p.title_mac)
        content_valid = verify_mac(decrypted_content, p.content_mac)

        decrypted_posts.append({
            'title': decrypted_title,
            'content': decrypted_content,
            'created_at': p.created_at,
            'title_valid': title_valid,
            'content_valid': content_valid
        })

    context = {'posts': decrypted_posts}
    return render(request, 'view_encrypted_post.html', context)
