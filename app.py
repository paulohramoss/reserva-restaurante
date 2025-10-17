from __future__ import annotations

from datetime import datetime, date
from typing import Optional

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import DateField, IntegerField, PasswordField, SelectField, StringField, TextAreaField, TimeField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, ValidationError
from flask_wtf import FlaskForm


MANAGER_ACCESS_CODE = "GESTOR2024"

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="customer")
    reservations = db.relationship("Reservation", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reservation_date = db.Column(db.Date, nullable=False)
    reservation_time = db.Column(db.Time, nullable=False)
    guests = db.Column(db.Integer, nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User", back_populates="reservations")


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return db.session.get(User, int(user_id))


class RegistrationForm(FlaskForm):
    name = StringField("Nome", validators=[DataRequired(), Length(max=120)])
    email = StringField("E-mail", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Senha", validators=[DataRequired(), Length(min=6, max=64)])
    confirm_password = PasswordField(
        "Confirmar Senha",
        validators=[DataRequired(), EqualTo("password", message="As senhas precisam ser iguais.")],
    )
    role = SelectField(
        "Tipo de Conta",
        choices=[("customer", "Cliente"), ("manager", "Gestor")],
        validators=[DataRequired()],
    )
    manager_code = StringField(
        "Código de Gestor",
        description="Informe o código fornecido pela administração para criar um acesso de gestor.",
    )

    def validate_email(self, field: StringField) -> None:  # type: ignore[override]
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError("Este e-mail já está cadastrado.")

    def validate_manager_code(self, field: StringField) -> None:  # type: ignore[override]
        if self.role.data == "manager" and field.data != MANAGER_ACCESS_CODE:
            raise ValidationError("Código de gestor inválido.")


class LoginForm(FlaskForm):
    email = StringField("E-mail", validators=[DataRequired(), Email()])
    password = PasswordField("Senha", validators=[DataRequired()])
    role = SelectField(
        "Entrar como",
        choices=[("customer", "Cliente"), ("manager", "Gestor")],
        validators=[DataRequired()],
    )


class ReservationForm(FlaskForm):
    reservation_date = DateField("Data", validators=[DataRequired()], format="%Y-%m-%d")
    reservation_time = TimeField("Horário", validators=[DataRequired()], format="%H:%M")
    guests = IntegerField("Número de Pessoas", validators=[DataRequired(), NumberRange(min=1, max=20)])
    notes = TextAreaField("Observações", validators=[Length(max=500)])

    def validate_reservation_date(self, field: DateField) -> None:  # type: ignore[override]
        if field.data < date.today():
            raise ValidationError("A data da reserva não pode ser no passado.")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-me-in-production"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        db.create_all()

    register_routes(app)
    return app


def register_routes(app: Flask) -> None:
    @app.context_processor
    def inject_globals():
        return {"current_year": datetime.utcnow().year}

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            flash("Você já está autenticado.", "info")
            return redirect(url_for("index"))

        form = RegistrationForm()
        if form.validate_on_submit():
            user = User(
                name=form.name.data.strip(),
                email=form.email.data.lower(),
                role=form.role.data,
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash("Cadastro realizado com sucesso!", "success")
            return redirect(url_for("login"))
        return render_template("register.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("index"))

        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data.lower(), role=form.role.data).first()
            if user and user.check_password(form.password.data):
                login_user(user)
                flash("Login realizado com sucesso!", "success")
                next_page = request.args.get("next")
                if next_page:
                    return redirect(next_page)
                if user.role == "manager":
                    return redirect(url_for("manager_dashboard"))
                return redirect(url_for("reserve"))
            flash("Credenciais inválidas.", "danger")
        return render_template("login.html", form=form)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Você saiu da sua conta.", "info")
        return redirect(url_for("index"))

    @app.route("/reserve", methods=["GET", "POST"])
    @login_required
    def reserve():
        if current_user.role != "customer":
            flash("Apenas clientes podem realizar reservas.", "warning")
            return redirect(url_for("manager_dashboard"))

        form = ReservationForm()
        if form.validate_on_submit():
            reservation = Reservation(
                user=current_user,
                reservation_date=form.reservation_date.data,
                reservation_time=form.reservation_time.data,
                guests=form.guests.data,
                notes=form.notes.data,
            )
            db.session.add(reservation)
            db.session.commit()
            flash("Reserva realizada com sucesso!", "success")
            return redirect(url_for("my_reservations"))
        return render_template("reserve.html", form=form)

    @app.route("/minhas-reservas")
    @login_required
    def my_reservations():
        if current_user.role != "customer":
            flash("Apenas clientes podem visualizar suas reservas.", "warning")
            return redirect(url_for("manager_dashboard"))
        reservations = (
            Reservation.query.filter_by(user_id=current_user.id)
            .order_by(Reservation.reservation_date, Reservation.reservation_time)
            .all()
        )
        return render_template("my_reservations.html", reservations=reservations)

    @app.route("/gestor", methods=["GET"])
    @login_required
    def manager_dashboard():
        if current_user.role != "manager":
            flash("Apenas gestores podem acessar o painel de reservas.", "warning")
            return redirect(url_for("reserve"))

        selected_date: Optional[str] = request.args.get("date")
        query = Reservation.query.order_by(Reservation.reservation_date, Reservation.reservation_time)
        if selected_date:
            try:
                parsed_date = datetime.strptime(selected_date, "%Y-%m-%d").date()
                query = query.filter(Reservation.reservation_date == parsed_date)
            except ValueError:
                flash("Data inválida informada para o filtro.", "danger")
        reservations = query.all()
        return render_template("manager_dashboard.html", reservations=reservations, selected_date=selected_date)


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
