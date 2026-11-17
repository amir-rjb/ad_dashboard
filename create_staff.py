from getpass import getpass
from app import app, db, User

with app.app_context():
    db.create_all()
    print("ساخت حساب کارمند سامانه")
    username = input("نام کاربری کارمند: ").strip()
    password = getpass("رمز عبور (حداقل ۸ کاراکتر): ")

    if len(username) < 3:
        print("نام کاربری باید حداقل ۳ کاراکتر باشد.")
    elif len(password) < 8:
        print("رمز عبور باید حداقل ۸ کاراکتر باشد.")
    elif User.query.filter_by(username=username).first():
        print("این نام کاربری قبلاً وجود دارد.")
    else:
        staff = User(username=username, role="staff")
        staff.set_password(password)
        db.session.add(staff)
        db.session.commit()
        print("حساب کارمند با موفقیت ساخته شد.")
