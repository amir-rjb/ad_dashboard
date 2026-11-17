import os
from datetime import datetime
from functools import wraps

from flask import Flask, abort, flash, redirect, render_template, request, url_for
from flask_login import (
    LoginManager, UserMixin, current_user, login_required,
    login_user, logout_user
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key-before-deployment")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, "ads.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024  # 3 MB
app.config["UPLOAD_FOLDER"] = os.path.join(app.static_folder, "uploads")

os.makedirs(app.instance_path, exist_ok=True)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "برای مشاهده این صفحه ابتدا وارد حساب خود شوید."
login_manager.login_message_category = "warning"

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
STATUSES = {
    "pending": "در انتظار بررسی",
    "approved": "تأیید و منتشر شده",
    "rejected": "رد شده",
}


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="requester")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    requests = db.relationship("AdRequest", backref="owner", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class AdRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(60), nullable=False)
    description = db.Column(db.Text, nullable=False)
    contact = db.Column(db.String(120), nullable=False)
    image_filename = db.Column(db.String(255))
    status = db.Column(db.String(20), nullable=False, default="pending")
    rejection_reason = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def staff_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if current_user.role != "staff":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def requester_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if current_user.role != "requester":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.context_processor
def inject_statuses():
    return {"STATUSES": STATUSES}


@app.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.role == "staff":
            return redirect(url_for("staff_dashboard"))
        return redirect(url_for("my_requests"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(username) < 3 or len(username) > 80:
            flash("نام کاربری باید بین ۳ تا ۸۰ کاراکتر باشد.", "error")
        elif len(password) < 8:
            flash("رمز عبور باید حداقل ۸ کاراکتر باشد.", "error")
        elif password != confirm:
            flash("تکرار رمز عبور با رمز اصلی یکسان نیست.", "error")
        elif User.query.filter_by(username=username).first():
            flash("این نام کاربری قبلاً ثبت شده است.", "error")
        else:
            user = User(username=username, role="requester")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("حساب شما ساخته شد. حالا وارد شوید.", "success")
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash("با موفقیت وارد شدید.", "success")
            return redirect(url_for("index"))

        flash("نام کاربری یا رمز عبور اشتباه است.", "error")

    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    logout_user()
    flash("از حساب خارج شدید.", "success")
    return redirect(url_for("index"))


@app.route("/request/new", methods=["GET", "POST"])
@requester_required
def new_request():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        category = request.form.get("category", "").strip()
        description = request.form.get("description", "").strip()
        contact = request.form.get("contact", "").strip()
        image = request.files.get("image")

        if not title or len(title) > 120:
            flash("عنوان الزامی است و حداکثر ۱۲۰ کاراکتر دارد.", "error")
        elif not category or not description or not contact:
            flash("همه فیلدهای ضروری را تکمیل کنید.", "error")
        elif len(description) > 3000:
            flash("توضیحات نباید بیشتر از ۳۰۰۰ کاراکتر باشد.", "error")
        elif len(contact) > 120:
            flash("اطلاعات تماس بیش از حد طولانی است.", "error")
        elif image and image.filename and not allowed_file(image.filename):
            flash("فرمت تصویر باید PNG، JPG، JPEG یا WEBP باشد.", "error")
        else:
            filename = None
            if image and image.filename:
                safe_name = secure_filename(image.filename)
                filename = f"{current_user.id}_{int(datetime.utcnow().timestamp())}_{safe_name}"
                image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

            ad = AdRequest(
                title=title,
                category=category,
                description=description,
                contact=contact,
                image_filename=filename,
                user_id=current_user.id,
            )
            db.session.add(ad)
            db.session.commit()
            flash("درخواست شما ثبت شد و در انتظار بررسی است.", "success")
            return redirect(url_for("my_requests"))

    return render_template("request_form.html")


@app.get("/my-requests")
@requester_required
def my_requests():
    # مالکیت با شناسه کاربرِ نشست‌شده تعیین می‌شود، نه ورودی مرورگر.
    ads = AdRequest.query.filter_by(user_id=current_user.id).order_by(AdRequest.created_at.desc()).all()
    return render_template("my_requests.html", ads=ads)


@app.get("/staff")
@staff_required
def staff_dashboard():
    status_filter = request.args.get("status", "all")
    query = AdRequest.query
    if status_filter in STATUSES:
        query = query.filter_by(status=status_filter)
    ads = query.order_by(AdRequest.created_at.desc()).all()

    counts = {
        "all": AdRequest.query.count(),
        "pending": AdRequest.query.filter_by(status="pending").count(),
        "approved": AdRequest.query.filter_by(status="approved").count(),
        "rejected": AdRequest.query.filter_by(status="rejected").count(),
    }
    return render_template("staff_dashboard.html", ads=ads, counts=counts, active_filter=status_filter)


@app.route("/staff/request/<int:ad_id>", methods=["GET", "POST"])
@staff_required
def review_request(ad_id):
    ad = db.get_or_404(AdRequest, ad_id)

    if request.method == "POST":
        action = request.form.get("action")
        if ad.status != "pending":
            flash("این درخواست قبلاً بررسی شده است.", "error")
            return redirect(url_for("staff_dashboard"))

        if action == "approve":
            ad.status = "approved"
            ad.rejection_reason = None
            ad.reviewed_at = datetime.utcnow()
            db.session.commit()
            flash("درخواست تأیید و آگهی منتشر شد.", "success")
            return redirect(url_for("staff_dashboard"))

        if action == "reject":
            reason = request.form.get("rejection_reason", "").strip()
            if not reason:
                flash("برای رد درخواست، دلیل آن را وارد کنید.", "error")
            elif len(reason) > 500:
                flash("دلیل رد نباید بیشتر از ۵۰۰ کاراکتر باشد.", "error")
            else:
                ad.status = "rejected"
                ad.rejection_reason = reason
                ad.reviewed_at = datetime.utcnow()
                db.session.commit()
                flash("درخواست رد شد.", "success")
                return redirect(url_for("staff_dashboard"))

    return render_template("review_request.html", ad=ad)


@app.get("/ads")
def published_ads():
    ads = AdRequest.query.filter_by(status="approved").order_by(AdRequest.reviewed_at.desc()).all()
    return render_template("published_ads.html", ads=ads)


@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403, message="شما اجازه دسترسی به این بخش را ندارید."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="صفحه یا آگهی موردنظر پیدا نشد."), 404


@app.errorhandler(413)
def file_too_large(error):
    flash("حجم تصویر نباید بیشتر از ۳ مگابایت باشد.", "error")
    return redirect(request.referrer or url_for("new_request"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
