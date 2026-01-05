from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
import os, json, random
from django.http import HttpResponse, HttpResponseForbidden
from datetime import datetime, timedelta
from django.contrib import messages
from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from .models import PasswordResetOTP, Section, UserSectionPermission



'''def sync_sections_from_apilist():
    # Normalize apilist (in case it's like ['users', 'orders'])
    from .url import apilist
    api_names = set(apilist)

    # Existing sections in DB
    db_sections = Section.objects.values_list("name", flat=True)
    db_names = set(db_sections)

    # ➕ Add new sections
    for name in api_names - db_names:
        Section.objects.create(name=name)

    # ❌ Delete removed sections
    Section.objects.filter(name__in=(db_names - api_names)).delete()'''





# -------------------- Permission Helpers --------------------

def get_user_section_permissions(user):
    """Returns dict {section_name: permission}"""
    if user.is_superuser:
        return {s.name: 'edit' for s in Section.objects.all()}

    perms = UserSectionPermission.objects.filter(user=user).select_related('section')
    return {p.section.name: p.permission for p in perms}


def user_can_view(user, section):
    if user.is_superuser:
        return True
    return UserSectionPermission.objects.filter(user=user, section__name=section).exists()


def user_can_edit(user, section):
    if user.is_superuser:
        return True
    return UserSectionPermission.objects.filter(user=user, section__name=section, permission='edit').exists()


# -------------------- User Authentication --------------------

def user_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect("dashboard")
       

        else:
            messages.error(request, "Invalid username or password")
    return render(request, "login.html")


def user_logout(request):
    logout(request)
    return redirect("login")


# -------------------- Dashboard --------------------


def get_section_map():
    return {
        s.name: s.path
        for s in Section.objects.all()
    }

@login_required
def dashboard(request):
    SECTION_MAP = get_section_map()

    # ---------------- USER PERMISSIONS ----------------
    userdetails = UserSectionPermission.objects.filter(user=request.user)
    detailist = []

    if request.user.is_superuser:
        for section in SECTION_MAP.keys():
            detailist.append({
                "section": section,
                "permission": "edit"
            })
    else:
        for detail in userdetails:
            detailist.append({
                "section": detail.section.name,
                "permission": detail.permission
            })

    # ---------------- ALL SECTIONS ----------------
    dir_stats = list(SECTION_MAP.keys())

    # ---------------- ALLOWED SECTIONS ----------------
    if request.user.is_superuser:
        allowed_sections = dir_stats
    else:
        user_perms = get_user_section_permissions(request.user)
        allowed_sections = [s for s in dir_stats if s in user_perms]

    # ✅ KEEP TEMPLATE FORMAT (NO `_root`)
    apilist_ui = [{item: item} for item in allowed_sections]
    

    # ---------------- ROOT MAP ----------------
    ROOT_MAP = {
        section: SECTION_MAP[section]
        for section in dir_stats
    }

    # ---------------- LOG SUMMARY ----------------
    now = datetime.now()
    #log_summary = {"last7": 0, "last30": 0, "last90": 0}
    log_summary = []
    section_counts = {}
    query_counts = {}
    log_files = []
    latesfile_created=['logs','sessions']
    for x in latesfile_created:
        logs_dir = ROOT_MAP.get(x, '')
        if logs_dir and os.path.exists(logs_dir):
            tempdict={'last7':0,'last30':0,'last90':0,'section':x}
            for f in os.listdir(logs_dir):
                full_path = os.path.join(logs_dir, f)
                if os.path.isfile(full_path):
                    log_files.append(full_path)
                    created_time = datetime.fromtimestamp(os.path.getmtime(full_path))
                    if created_time >= now - timedelta(days=7):
                        #log_summary['last7'] 
                        tempdict['last7'] += 1
                    if created_time >= now - timedelta(days=30):
                        #log_summary['last30'] += 1
                        tempdict['last30'] += 1
                    if created_time >= now - timedelta(days=90):
                        #log_summary['last90'] += 1
                        tempdict['last90'] += 1
            log_summary.append(tempdict)
    # ---------------- SECTION FILE/FOLDER COUNTS ----------------
    for key, path in ROOT_MAP.items():
        files = folders = 0
        if os.path.exists(path):
            for _, dirs, fs in os.walk(path):
                files += len(fs)
                folders += len(dirs)
        section_counts[key] = {
            "files": files,
            "folders": folders
        }


   
    allowed_section_names = [s for s in allowed_sections]
    apilist_ui = sorted(apilist_ui, key=lambda d: list(d.keys())[0])
    # ---------------- CONTEXT ----------------
    context = {
    "log_summary": log_summary,
    "section_counts": section_counts,
    "query_counts": query_counts,
    "apilist": apilist_ui,
    "userdetail": detailist,
    "allowed_section_names": allowed_section_names,  # <-- add this
        }
    return render(request, "dashboard.html", context)


# -------------------- File Browser --------------------






@login_required
def browser(request, section=None, filename=''):
    import os, json
    from urllib.parse import unquote
    from datetime import datetime
    from django.http import HttpResponseForbidden

    SECTION_MAP = get_section_map()

    userdetails = UserSectionPermission.objects.filter(user=request.user)
    detailist = []

    if request.user.is_superuser:
        for sec in SECTION_MAP.keys():
            detailist.append({"section": sec, "permission": "edit"})
    else:
        for detail in userdetails:
            detailist.append({
                "section": detail.section.name,
                "permission": detail.permission
            })

    # ---------------- Allowed sections ----------------
    all_sections = list(SECTION_MAP.keys())

    if request.user.is_superuser:
        allowed_sections = all_sections
    else:
        perms = get_user_section_permissions(request.user)
        allowed_sections = [s for s in all_sections if s in perms]

    if section not in allowed_sections:
        return HttpResponseForbidden("Invalid or unauthorized section")

    basepath = os.path.abspath(SECTION_MAP[section])

    apilist_ui = [{s: s} for s in allowed_sections]
    apilist_ui = sorted(apilist_ui, key=lambda d: list(d.keys())[0])
    # ---------------- Permissions ----------------
    can_edit = request.user.is_superuser or user_can_edit(request.user, section)

    # ---------------- Normalize filename ----------------
    filename = unquote(filename).strip("/")

    # ---------------- Breadcrumbs ----------------
    breadcrumbs = [{"name": section, "url": f"/{section}/"}]

    if filename:
        parts = filename.split("/")
        cumulative = ""
        for part in parts:
            cumulative = f"{cumulative}/{part}" if cumulative else part
            breadcrumbs.append({
                "name": part,
                "url": f"/{section}/{cumulative}"
            })

    # ---------------- Resolve absolute path ----------------
    current_path = os.path.abspath(
        os.path.join(basepath, filename) if filename else basepath
    )

    if not current_path.startswith(basepath):
        return HttpResponseForbidden("Invalid path")

    def build_path_list(abs_path, rel_prefix=""):
        folders = []
        files = []

        for name in os.listdir(abs_path):
            full = os.path.join(abs_path, name)
            stat = os.stat(full)

            item = {
                "name": name,
                "path": f"{rel_prefix}/{name}".lstrip("/"),
                "is_file": os.path.isfile(full),
                "size": stat.st_size if os.path.isfile(full) else None,
                "created": datetime.fromtimestamp(stat.st_ctime),
                "modified": datetime.fromtimestamp(stat.st_mtime),
                "userdetail": detailist
            }

            if os.path.isdir(full):
                folders.append(item)
            else:
                files.append(item)

        # 📁 Folders → A–Z
        folders.sort(key=lambda x: x["name"].lower())

        # 📄 Files → newest CREATED first
        files.sort(key=lambda x: x["created"], reverse=True)
        if section == "sessions" or "logs":
            files = files[:1000]
        return folders + files


    # ---------------- Directory view ----------------
    if os.path.isdir(current_path):
        return render(request, "base.html", {
            "path": build_path_list(current_path, filename),
            "section": section,
            "basepath": basepath,
            "apilist": apilist_ui,
            "can_edit": can_edit,
            "breadcrumbs": breadcrumbs,
            "userdetail": detailist
        })

    # ---------------- File view ----------------
    try:
        with open(current_path, "r", encoding="utf-8") as f:
            if current_path.endswith(".json"):
                try:
                    content = json.dumps(json.load(f), indent=4)
                except json.JSONDecodeError:
                    f.seek(0)
                    content = f.read()
            else:
                content = f.read()
    except Exception as e:
        content = str(e)

    parent_dir = os.path.dirname(filename)
    parent_abs = os.path.join(basepath, parent_dir) if parent_dir else basepath
    apilist_ui = sorted(apilist_ui, key=lambda d: list(d.keys())[0])
    
    return render(request, "base.html", {
        "content": content,
        "path": build_path_list(parent_abs, parent_dir),
        "section": section,
        "basepath": basepath,
        "pathforupdate": current_path,
        "apilist": apilist_ui,
        "can_edit": can_edit,
        "breadcrumbs": breadcrumbs,
        "userdetail": detailist
    })





# -------------------- Update Data --------------------


@login_required
def updatedata(request, filename):
    if request.method != "POST":
        return HttpResponse("Invalid request", status=400)

    from urllib.parse import unquote
    SECTION_MAP=get_section_map()
    # ---------------- Decode & normalize path ----------------
    filename = unquote(filename)
    filename = os.path.abspath(os.path.normpath(filename))

    # ---------------- Detect section using SECTION_MAP ----------------
    section = None
    basepath = None

    for sec, path in SECTION_MAP.items():
        abs_path = os.path.abspath(path)
        if filename.startswith(abs_path + os.sep) or filename == abs_path:
            section = sec
            basepath = abs_path
            break

    if not section:
        return HttpResponseForbidden("Invalid path or section")

    # ---------------- Permission check ----------------
    if not (request.user.is_superuser or user_can_edit(request.user, section)):
        return HttpResponseForbidden("Edit permission denied")

    # ---------------- Security: prevent path escape ----------------
    if not filename.startswith(basepath):
        return HttpResponseForbidden("Invalid file path")

    # ---------------- Get content ----------------
    content = request.POST.get('content', '')
    is_json = filename.endswith(".json")

    # ---------------- JSON validation ----------------
    python_obj = None
    if is_json:
        if content.strip() != "":
            try:
                python_obj = json.loads(content)
            except json.JSONDecodeError:
                messages.error(request, "Incorrect JSON format. File not saved.")
                return redirect(request.META.get("HTTP_REFERER", "/"))

    # ---------------- Save file ----------------
    try:
        with open(filename, "w", encoding="utf-8", newline="") as f:
            if is_json:
                if python_obj is not None:
                    json.dump(python_obj, f, indent=2)
                # else → keep file empty
            else:
                f.write(content)

        messages.success(request, "Your file has been saved")

    except Exception as e:
        messages.error(request, f"Error saving file: {e}")

    return redirect(request.META.get("HTTP_REFERER", "/"))



# -------------------- Forgot Password --------------------

def forgot_password(request):
    step = 1
    error = ""
    success = ""

    if request.method == "POST":
        if "email" in request.POST:
            email = request.POST.get("email")
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                error = "Email not registered"
            else:
                otp = str(random.randint(100000, 999999))
                PasswordResetOTP.objects.filter(user=user).delete()
                PasswordResetOTP.objects.create(user=user, otp_code=otp)

                send_mail(
                    subject="Password Reset Code",
                    message=f"Your password reset code is: {otp}",
                    from_email=None,
                    recipient_list=[email],
                )

                request.session["reset_user"] = user.id
                success = "OTP sent to your email"
                step = 2

        elif "otp" in request.POST and "password" in request.POST:
            user_id = request.session.get("reset_user")
            if not user_id:
                error = "Session expired. Start again."
                step = 1
            else:
                otp = request.POST.get("otp")
                new_password = request.POST.get("password")
                try:
                    record = PasswordResetOTP.objects.get(user_id=user_id, otp_code=otp)
                except PasswordResetOTP.DoesNotExist:
                    error = "Invalid code"
                    step = 2
                else:
                    if (timezone.now() - record.created_at).seconds > 300:
                        record.delete()
                        error = "Code expired"
                        step = 1
                    else:
                        user = record.user
                        user.password = make_password(new_password)
                        user.save()
                        record.delete()
                        del request.session["reset_user"]
                        success = "Password updated successfully"
                        step = 1
                        return redirect('login')

    else:
        if "reset_user" in request.session:
            step = 2

    return render(request, "forgot_password.html", {
        "step": step,
        "error": error,
        "success": success
    })
add = "('getusername/', views.getuser, name='getuser')"
@login_required
def getuser(request,username):
    print(username)
    pass


