from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from datetime import datetime, date, timedelta, timezone
from functools import wraps
from collections import Counter
from sqlalchemy import func, case, cast, Float
from sqlalchemy.orm import joinedload # <--- ASEGÚRATE DE QUE ESTO ESTÉ AL INICIO DEL ARCHIVO
import pytz
import json # Import necesario para procesar el JSON de Compra
import os



app = Flask(__name__)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
#app.config['SECRET_KEY'] = 'mi_clave_secreta_debe_ser_larga_y_unica'
#app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
#app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.jinja_env.globals.update(abs=abs)
#db = SQLAlchemy(app)

# ----------------------------------------------------
# 1. CONFIGURACIÓN INICIAL DE LA APLICACIÓN
# ----------------------------------------------------
#database_url = os.environ.get('DATABASE_URL', 'sqlite:///tu_db_local.db')
# Si usas Render, tendrás que agregar este parámetro:
#if database_url.startswith("postgres://"):
#    database_url = database_url.replace("postgres://", "postgresql://", 1)



# =======================================================
# NUEVO BLOQUE CRÍTICO PARA EL DESPLIEGUE GRATUITO EN RENDER
# Esto fuerza la creación de tablas al inicio si no existen.
# =======================================================
#with app.app_context():
    # Usar db.create_all() si las tablas no existen.
    # NOTA: Esto solo crea tablas, no maneja migraciones complejas.
#    try:
#        db.create_all()
#        print("INFO: Las tablas de la base de datos han sido creadas (o ya existían).")
#    except Exception as e:
#        print(f"ADVERTENCIA: Falló la creación de tablas, puede que ya existan o haya un error de DB: {e}")
# =======================================================

# 1. Obtiene el valor de la variable de entorno
db_uri = os.environ.get('DATABASE_URL')

# 2. Configura Flask (asegúrese de usar 'db_uri', no un nombre indefinido)
if db_uri is None:
    db_uri = 'sqlite:///site.db' # Fallback local

app.config['SQLALCHEMY_DATABASE_URI'] = db_uri # <-- Aquí la variable DEBE COINCIDIR con la de arriba
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)



# Configuración del sistema de Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, inicie sesión para acceder a esta página."
login_manager.login_message_category = "info"

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'Admin':
            flash('Acceso denegado. Se requiere rol de Administrador.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Función para cargar el usuario en Flask-Login
@login_manager.user_loader
def load_user(user_id):
    # Uso de .get()
    return db.session.get(User, int(user_id))


# --- FUNCIÓN AUXILIAR DE TIEMPO ---
def now_lima():
    """Retorna la hora actual de Lima (UTC-5) como un datetime Naive,
    compatible con SQLite/SQLAlchemy que no manejan zonas horarias."""
    lima_tz = pytz.timezone('America/Lima')
    # Obtenemos la hora aware y la convertimos a Naive (sin tzinfo) para la DB
    return datetime.now(lima_tz).replace(tzinfo=None)


# ----------------------------------------------------
# 2. MODELOS DE BASE DE DATOS (SQLAlchemy)
# ----------------------------------------------------
# 1. CLASE USER (Usuario)
class User(UserMixin, db.Model):
    # Opcional: Nombre explícito de la tabla (Buena práctica en SQLAlchemy)
    # __tablename__ = 'usuario'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    # Campo 'role' correcto.
    role = db.Column(db.String(50), default='Empleado', nullable=False) 
    # nullable=True es correcto para un Admin sin farmacia asignada.
    farmacia_id = db.Column(db.Integer, db.ForeignKey('farmacia.id'), nullable=True)

    # Relaciones (Se mantienen los nombres 'back_populates' para no romper el código asociado)
    farmacia = db.relationship('Farmacia', back_populates='empleados_rel')
    ventas_realizadas = db.relationship('Sale', back_populates='vendedor_rel')
    ajustes_realizados = db.relationship('AjusteStock', back_populates='user_rel', foreign_keys='[AjusteStock.user_id]') 

    # --- Métodos de Autenticación (Correctos) ---
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # ------------------------------------------------------------------
    # ✅ MEJORA: Propiedades para Comprobación de Roles (Mejor legibilidad)
    # ------------------------------------------------------------------
    @property
    def is_admin(self):
        """Devuelve True si el rol del usuario es 'Admin'."""
        return self.role == 'Admin'

    @property
    def is_empleado(self):
        """Devuelve True si el rol del usuario es 'Empleado'."""
        return self.role == 'Empleado'

    # --- Representación del Objeto ---
    def __repr__(self):
        # Uso de !r para una mejor representación de string dentro de la f-string
        return f"<User {self.username!r} - Role: {self.role!r}>"


# 2. CLASE FARMACIA (Sucursal)
class Farmacia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), unique=True, nullable=False)

    # Relaciones
    inventario_rel = db.relationship('Inventario', back_populates='farmacia_rel', cascade="all, delete-orphan")
    empleados_rel = db.relationship('User', back_populates='farmacia', cascade="all, delete-orphan")
    ventas_rel = db.relationship('Sale', back_populates='sucursal_venta_rel', cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Farmacia {self.nombre}>"

# 3. CLASE INVENTARIO (Producto por Sucursal)
class Inventario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    farmacia_id = db.Column(db.Integer, db.ForeignKey('farmacia.id'), nullable=False)
    nombre = db.Column(db.String(255), nullable=False)
    stock = db.Column(db.Integer, default=0)
    
    # Precios y Costos
    precio_de_venta = db.Column(db.Float, default=0.0) # Precio final al público
    costo_promedio = db.Column(db.Float, default=0.0) # Costo Promedio Ponderado (PMP)

    # Relaciones
    farmacia_rel = db.relationship('Farmacia', back_populates='inventario_rel')
    compras_rel = db.relationship('Compra', back_populates='inventario_rel', cascade="all, delete-orphan")
    ventas_rel = db.relationship('Sale', back_populates='inventario', cascade="all, delete-orphan")
    ajustes_stock = db.relationship('AjusteStock', back_populates='inventario_rel', cascade="all, delete-orphan") # Nuevo

    __table_args__ = (db.UniqueConstraint('farmacia_id', 'nombre', name='_farmacia_nombre_uc'),)

    def __repr__(self):
        return f"<Inventario {self.nombre} ({self.farmacia_id}) - Stock: {self.stock}>"

# 4. CLASE COMPRA (Registro de Ingreso de Producto)
class Compra(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    inventario_id = db.Column(db.Integer, db.ForeignKey('inventario.id'), nullable=False)
    cantidad = db.Column(db.Integer, nullable=False)
    costo_unitario = db.Column(db.Float, nullable=False)
    fecha_compra = db.Column(db.DateTime, default=datetime.utcnow)

    # Relaciones
    inventario_rel = db.relationship('Inventario', back_populates='compras_rel')

    def __repr__(self):
        return f"<Compra {self.inventario_id} - {self.cantidad} @ {self.costo_unitario}>"

# 5. CLASE SALE (Venta)
class Sale(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    inventario_id = db.Column(db.Integer, db.ForeignKey('inventario.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 
    farmacia_id = db.Column(db.Integer, db.ForeignKey('farmacia.id'), nullable=False)
    
    nombre_producto = db.Column(db.String(255), nullable=False) 
    cantidad = db.Column(db.Integer, nullable=False)
    precio_con_descuento = db.Column(db.Float, nullable=False)
    total = db.Column(db.Float, nullable=False)
    
    # Campo para utilidad
    costo_unitario_venta = db.Column(db.Float, nullable=False, default=0.0) 
    fecha_venta = db.Column(db.DateTime, default=now_lima)

    # DATOS DE PAGO
    metodo_pago = db.Column(db.String(50), nullable=True, default='Efectivo') 
    monto_pagado = db.Column(db.Float, nullable=True, default=0.0)
    
    # CAMPOS AÑADIDOS PARA EL PAGO MIXTO (Si es Mixto, monto_pagado = efectivo + yape)
    monto_efectivo_mixto = db.Column(db.Float, nullable=True, default=0.0)
    monto_yape_mixto = db.Column(db.Float, nullable=True, default=0.0)

    # Relaciones...
    inventario = db.relationship('Inventario', back_populates='ventas_rel') 
    vendedor_rel = db.relationship('User', back_populates='ventas_realizadas')
    sucursal_venta_rel = db.relationship('Farmacia', primaryjoin='Farmacia.id == Sale.farmacia_id', back_populates='ventas_rel')

    def __repr__(self):
        return f"<Sale {self.nombre_producto} - {self.total:.2f}>"

# 6. CLASE AjusteStock (Registro de Ajustes Manuales de Inventario) 
class AjusteStock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    inventario_id = db.Column(db.Integer, db.ForeignKey('inventario.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Quién hizo el ajuste
    
    # ✅ CAMPO AÑADIDO: VITAL para filtrar ajustes por sucursal en el reporte global
    farmacia_id = db.Column(db.Integer, db.ForeignKey('farmacia.id'), nullable=False)

    # El campo datetime se define una sola vez
    fecha_ajuste = db.Column(db.DateTime, default=datetime.utcnow)
    
    cantidad_anterior = db.Column(db.Integer, nullable=False)
    cantidad_ajustada = db.Column(db.Integer, nullable=False) # Nuevo stock después del ajuste
    diferencia = db.Column(db.Integer, nullable=False) # Cantidad (+/-) que se movió
    motivo = db.Column(db.String(255), nullable=True) # Por qué se hizo el ajuste

    # ✅ CAMPO AÑADIDO: Costo unitario utilizado en el momento del ajuste
    costo_unitario_ajuste = db.Column(db.Float, nullable=False)
    
    # CLAVE: Pérdida/Ganancia en valor monetario por el ajuste
    diferencia_valorizada = db.Column(db.Float, nullable=False) 

    # ✅ CAMPO AÑADIDO: Para distinguir si es 'Pérdida' o 'Ganancia' (Reporte)
    tipo_movimiento = db.Column(db.String(50), nullable=False)


    # Relaciones (Asegúrese de que el back_populates coincida con sus otros modelos)
    inventario_rel = db.relationship('Inventario', back_populates='ajustes_stock')
    user_rel = db.relationship('User', back_populates='ajustes_realizados')
    # ✅ RELACIÓN AÑADIDA: Para la Farmacia
    farmacia_rel = db.relationship('Farmacia', backref='ajustes_stock', lazy=True)
    
    def __repr__(self):
        return f"<Ajuste {self.inventario_id} - Diff: {self.diferencia}>"


# 7. CLASE CIERRECAJA (Registro del Cierre de Turno/Día)
# app.py (Reemplace la CLASE CIERRECAJA completa)

class CierreCaja(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    farmacia_id = db.Column(db.Integer, db.ForeignKey('farmacia.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Quién realizó el cierre
    
    fecha_cierre = db.Column(db.DateTime, default=datetime.utcnow) # Momento del registro
    
    # Montos ingresados por el usuario
    fondo_fijo = db.Column(db.Float, nullable=False)
    tarjeta_yape_fisico = db.Column(db.Float, nullable=False) # Monto contado por el usuario (Tarjeta/Yape)
    efectivo_contado = db.Column(db.Float, nullable=False)     # Monto contado por el usuario (Efectivo)
    
    # Montos CALCULADOS y registrados (para auditoría)
    ventas_totales_sistema = db.Column(db.Float, nullable=False)
    efectivo_esperado = db.Column(db.Float, nullable=False) # Solo ventas de efectivo registradas
    tarjeta_yape_esperado = db.Column(db.Float, nullable=False) # Total Tarjeta/Yape Registrado en DB

    # Resultado del cuadre
    diferencia_efectivo = db.Column(db.Float, nullable=False) # efectivo_contado vs (fondo_fijo + efectivo_esperado)
    diferencia_tarjeta = db.Column(db.Float, nullable=False) # <--- CAMBIO CLAVE AÑADIDO
    
    # Relaciones
    farmacia_rel = db.relationship('Farmacia', backref='cierres_caja', lazy=True)
    user_rel = db.relationship('User', backref='cierres_realizados', lazy=True)
    
    def __repr__(self):
        return f"<CierreCaja {self.id} - Dif: {self.diferencia_efectivo:.2f}>"

# app.py: MODELO CashClose CORREGIDO
class CashClose(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    farmacia_id = db.Column(db.Integer, db.ForeignKey('farmacia.id'), nullable=False)
    close_time = db.Column(db.DateTime, default=datetime.utcnow) 
    total_reported = db.Column(db.Float, nullable=False) 
    
    # Corregido: Usamos nombres más específicos para evitar el conflicto
    # 'cierres_caja_vendedor' para la referencia inversa en User
    user = db.relationship('User', backref='cierres_caja_vendedor')
    # 'cierres_caja_data' para la referencia inversa en Farmacia
    farmacia = db.relationship('Farmacia', backref='cierres_caja_data')

# ----------------------------------------------------
# 3. RUTAS Y LÓGICA DE LA APLICACIÓN
# ----------------------------------------------------

@app.before_request
def create_default_data():
    if request.path.startswith('/static') or request.path.startswith('/favicon'):
        return
        
    # Importante: Solo debe intentar crear las tablas una vez que la base de datos esté lista
    # En un entorno de desarrollo con SQLite, db.create_all() está bien aquí.
    with app.app_context():
        db.create_all()
        
        # Crear un usuario administrador por defecto si no existe
        if User.query.filter_by(username='admin').first() is None:
            admin = User(username='admin', role='Admin')
            admin.set_password('adminpass')
            db.session.add(admin)
            db.session.commit()
            
        # Crear una farmacia por defecto si no existe
        farmacia_central = Farmacia.query.filter_by(nombre='Farmacia Central').first()
        if farmacia_central is None:
            farmacia_central = Farmacia(nombre='Farmacia Central')
            db.session.add(farmacia_central)
            db.session.commit()
            
            # Asignar la farmacia al admin si no está asignada
            admin = User.query.filter_by(username='admin').first()
            if admin and admin.farmacia_id is None:
                admin.farmacia_id = farmacia_central.id
                db.session.commit()


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash(f'¡Bienvenido, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Nombre de usuario o contraseña incorrectos.', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Ha cerrado su sesión correctamente.', 'info')
    return redirect(url_for('login'))


# ----------------------------------------------------
# 4. FUNCIONES CRUD BÁSICAS (Farmacia, Usuarios, Compras)
# ----------------------------------------------------

@app.route('/gestion-usuarios', methods=['GET', 'POST'])
@login_required
@admin_required
def gestion_usuarios():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        role = request.form.get('role')
        farmacia_id = request.form.get('farmacia_id')
        
        # Validación
        if not username or not password or not role:
            flash('Todos los campos son obligatorios.', 'danger')
            return redirect(url_for('gestion_usuarios'))

        # Excluir la verificación de existencia si se trata de una edición (aunque esta ruta es principalmente para creación)
        if User.query.filter_by(username=username).first():
            flash('Ya existe un usuario con ese nombre.', 'danger')
            return redirect(url_for('gestion_usuarios'))
            
        try:
            # Si farmacia_id es "0" o None, se guarda como NULL
            farmacia_id_int = int(farmacia_id) if farmacia_id and farmacia_id != '0' else None
            
            new_user = User(username=username, role=role, farmacia_id=farmacia_id_int)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash(f'Usuario "{username}" creado con éxito.', 'success')
            return redirect(url_for('gestion_usuarios'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear el usuario: {str(e)}', 'danger')
            return redirect(url_for('gestion_usuarios'))
    
    # Lógica GET
    users = User.query.all()
    farmacias = Farmacia.query.all()
    return render_template('gestion_usuarios.html', users=users, farmacias=farmacias)

@app.route('/editar-usuario/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def editar_usuario(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('gestion_usuarios'))

    farmacias = Farmacia.query.all()
    
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        role = request.form.get('role')
        farmacia_id = request.form.get('farmacia_id')
        
        # Validación de unicidad de username (excepto para el usuario actual)
        if User.query.filter(User.username == username, User.id != user_id).first():
            flash('Ya existe otro usuario con ese nombre.', 'danger')
            return redirect(url_for('editar_usuario', user_id=user_id))
            
        try:
            user.username = username
            user.role = role
            # Si farmacia_id es "0" o None, se guarda como NULL (Esto es correcto)
            user.farmacia_id = int(farmacia_id) if farmacia_id and farmacia_id != '0' else None
            
            if password:
                # Asegúrate de que 'set_password' utiliza hashing (ej: generate_password_hash)
                user.set_password(password)
            
            db.session.commit()
            flash(f'Usuario "{username}" actualizado con éxito.', 'success')
            return redirect(url_for('gestion_usuarios'))
        
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar el usuario: {str(e)}', 'danger')
            return redirect(url_for('editar_usuario', user_id=user_id))

    # CAMBIO CLAVE: Cambiado 'botica' a 'boticas' para que Jinja2 pueda iterar en el template.
    return render_template('editar_usuario.html', user=user, boticas=farmacias)

# ✅ RUTA QUE FALTABA Y CAUSABA EL ERROR (eliminar_usuario)
@app.route('/eliminar-usuario/<int:user_id>')
@login_required
@admin_required
def eliminar_usuario(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('gestion_usuarios'))
    
    if user.id == current_user.id:
        flash('No puedes eliminar tu propia cuenta mientras estás logueado.', 'danger')
        return redirect(url_for('gestion_usuarios'))

    try:
        username_deleted = user.username
        db.session.delete(user)
        db.session.commit()
        flash(f'Usuario "{username_deleted}" eliminado correctamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar el usuario "{user.username}". Detalle: {e}', 'error')
        
    return redirect(url_for('gestion_usuarios'))


@app.route('/agregar-farmacia', methods=['GET', 'POST'])
@login_required
@admin_required
def agregar_farmacia():
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        if not nombre:
            flash('El nombre de la farmacia es obligatorio.', 'error')
            return redirect(url_for('agregar_farmacia'))
        
        if Farmacia.query.filter_by(nombre=nombre).first():
            flash('Ya existe una farmacia con ese nombre.', 'error')
            return redirect(url_for('agregar_farmacia'))
            
        nueva_farmacia = Farmacia(nombre=nombre)
        db.session.add(nueva_farmacia)
        db.session.commit()
        flash(f'Farmacia "{nombre}" creada correctamente.', 'success')
        return redirect(url_for('agregar_farmacia'))
        
    farmacias = Farmacia.query.all()
    return render_template('agregar_farmacia.html', farmacias=farmacias)

@app.route('/eliminar-farmacia/<int:id>')
@login_required
@admin_required
def eliminar_farmacia(id):
    # Uso de db.session.get()
    botica = db.session.get(Farmacia, id)
    if not botica:
        flash('Sucursal no encontrada.', 'danger')
        return redirect(url_for('agregar_farmacia'))
    try:
        nombre_eliminado = botica.nombre
        db.session.delete(botica)
        db.session.commit()
        flash(f'Botica "{nombre_eliminado}" eliminada correctamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar la botica "{botica.nombre}". Asegúrese de que no tenga inventario, usuarios o ventas asociadas. Detalle: {e}', 'error')
        
    return redirect(url_for('agregar_farmacia'))

# ----------------------------------------------------
# 5. LÓGICA DE COMPRAS (Calculo de PMP)
# ----------------------------------------------------

@app.route('/registro-compra', methods=['GET', 'POST'])
@login_required
@admin_required
def registro_compra():
    # ------------------ LÓGICA POST (ENTRADA MASIVA) ------------------
    if request.method == 'POST':
        try:
            # 1. Obtener la ID de la farmacia y la data JSON de la lista de compras
            farmacia_id = request.form.get('farmacia_id') 
            lista_compras_data = request.form.get('listaComprasData')
            
            # Validación inicial
            if not farmacia_id or farmacia_id == '0':
                 flash('Debe seleccionar una Sucursal de Destino.', 'error')
                 return redirect(url_for('registro_compra'))

            if not lista_compras_data:
                flash('No hay productos en la lista para registrar la compra.', 'error')
                return redirect(url_for('registro_compra'))
                
            productos_a_comprar = json.loads(lista_compras_data)
            
            if not productos_a_comprar:
                flash('La lista de compras está vacía.', 'error')
                return redirect(url_for('registro_compra'))

            farmacia_id = int(farmacia_id) # Convertir después de validar que no es None/vacio

        except json.JSONDecodeError:
            flash('Error al decodificar la lista de compras (JSON inválido).', 'error')
            return redirect(url_for('registro_compra'))
        except (ValueError, TypeError) as e:
            # Esto captura si farmacia_id no es un número válido.
            flash(f'Error de formato al recibir datos: {e}. Asegúrese de que la sucursal está bien seleccionada.', 'error')
            return redirect(url_for('registro_compra'))
        
        # ------------------ PROCESAMIENTO DE ITEMS ------------------
        farmacia = Farmacia.query.get(farmacia_id)
        if not farmacia:
            flash('Sucursal de destino no encontrada.', 'error')
            return redirect(url_for('registro_compra'))

        total_items_added = 0
        
        try:
            for item in productos_a_comprar:
                # 2. Extraer y validar datos del item (vienen del JSON)
                nombre_producto = item.get('nombre', '').strip()
                cantidad = int(item.get('cantidad_comprada', 0))
                costo_total_compra = float(item.get('costo_total_compra', 0.0))
                precio_de_venta = float(item.get('precio_de_venta', 0.0))
                
                # Validación de campos de cada ítem
                if not nombre_producto or cantidad <= 0 or costo_total_compra <= 0 or precio_de_venta <= 0:
                     raise ValueError(f"Datos inválidos para el producto: {nombre_producto}. Cantidad, Costo Total y Precio de Venta deben ser positivos.")

                # Calcular costo unitario (Costo por unidad de este ingreso)
                costo_unitario = costo_total_compra / cantidad
                
                # 3. Buscar o crear el producto en el inventario de esa farmacia
                producto = Inventario.query.filter_by(
                    farmacia_id=farmacia_id, 
                    nombre=nombre_producto
                ).first()
                
                # 4. Actualizar/Crear Producto (Lógica de PMP)
                if producto:
                    # Producto existente: Calcular nuevo Costo Promedio Ponderado (PMP)
                    valor_antiguo = producto.stock * producto.costo_promedio
                    valor_nuevo = costo_total_compra
                    
                    nuevo_stock_total = producto.stock + cantidad
                    
                    if nuevo_stock_total > 0:
                        nuevo_pmp = (valor_antiguo + valor_nuevo) / nuevo_stock_total
                    else:
                        nuevo_pmp = producto.costo_promedio 
                        
                    producto.stock = nuevo_stock_total
                    producto.costo_promedio = nuevo_pmp
                    producto.precio_de_venta = precio_de_venta 
                else:
                    # Nuevo producto
                    producto = Inventario(
                        farmacia_id=farmacia_id,
                        nombre=nombre_producto,
                        stock=cantidad,
                        costo_promedio=costo_unitario, # El costo unitario es el PMP inicial
                        precio_de_venta=precio_de_venta
                    )
                    db.session.add(producto)
                
                # 5. Registrar la compra
                db.session.flush() # Obtener el ID del producto si es nuevo
                nueva_compra = Compra(
                    inventario_id=producto.id,
                    cantidad=cantidad,
                    costo_unitario=costo_unitario,
                )
                db.session.add(nueva_compra)
                total_items_added += 1
            
            db.session.commit()
            
            flash(f'Ingreso Masivo completado: {total_items_added} productos(s) registrados/actualizados en {farmacia.nombre}.', 'success')
            return redirect(url_for('registro_compra'))

        except Exception as e:
            db.session.rollback()
            # Este es un error general durante la iteración (ej: ValueError en int(), float())
            flash(f'Error al procesar la lista de compras. Detalle: {str(e)}', 'error')
            return redirect(url_for('registro_compra'))


    # ------------------ LÓGICA GET ------------------
    farmacias = Farmacia.query.all()
    
    # Obtener un producto de referencia (si existe) para el JS de precio_anterior
    producto_referencia = None
    if farmacias:
        # Intentar obtener un producto de la primera farmacia para dar un valor de referencia inicial
        producto_referencia = Inventario.query.filter_by(farmacia_id=farmacias[0].id).order_by(Inventario.nombre).first()
    
    # Esto ayuda al JS a saber si hay datos iniciales de referencia
    producto_referencia_json = json.dumps({
        'nombre': producto_referencia.nombre, 
        'precio_de_venta': producto_referencia.precio_de_venta
    }) if producto_referencia else '{}'

    return render_template('registro_compra.html', 
                           farmacias=farmacias,
                           producto_referencia_json=producto_referencia_json
    )

# ----------------------------------------------------
# 6. RUTAS DE VENTA (Corregidas para Descuento)
# ----------------------------------------------------

@app.route('/seleccionar-farmacia-ventas', methods=['GET'])
@login_required
def seleccionar_farmacia_ventas():
    # Solo el administrador puede usar este selector
    if current_user.role != 'Admin':
        # Si no es admin, redirige a su propia pantalla de ventas
        return redirect(url_for('pantalla_ventas')) 

    todas_las_farmacias = Farmacia.query.all()
    return render_template('select_farmacia_ventas.html', farmacias=todas_las_farmacias)


@app.route('/pantalla-ventas/<int:farmacia_id>', methods=['GET'])
@login_required
def pantalla_ventas_admin(farmacia_id):
    if current_user.role != 'Admin':
        flash('Acceso denegado. No tiene permiso para seleccionar sucursal.', 'danger')
        return redirect(url_for('dashboard'))
        
    farmacia = Farmacia.query.get_or_404(farmacia_id)
    # Redirige a la ruta base con el parámetro, para que la lógica principal lo maneje
    return redirect(url_for('pantalla_ventas', farmacia_id=farmacia_id))


# --- [ CÓDIGO CORREGIDO EN app.py ] ---
# ... (otras importaciones y código de configuración de Flask)

@app.route('/pantalla-ventas', methods=['GET', 'POST'])
@login_required
def pantalla_ventas():
    
    farmacia_id_param = request.args.get('farmacia_id', type=int)

    # 1. Determinar la farmacia actual
    if current_user.role == 'Admin' and farmacia_id_param:
        farmacia_actual = Farmacia.query.get(farmacia_id_param)
        if not farmacia_actual:
            flash("Sucursal seleccionada no encontrada.", "error")
            return redirect(url_for('seleccionar_farmacia_ventas'))
    elif current_user.farmacia_id:
        farmacia_actual = Farmacia.query.get(current_user.farmacia_id)
    else:
        flash("No tiene una sucursal asignada para realizar ventas.", "error")
        return redirect(url_for('dashboard'))

    if not farmacia_actual:
        flash("No se pudo determinar la sucursal de ventas.", "error")
        return redirect(url_for('dashboard'))

    # 2. Lógica POST para procesar venta
    if request.method == 'POST':
        data = request.get_json()
        productos_vendidos = data.get('productos')
        
        # Extracción de campos de pago
        metodo_pago = data.get('metodo_pago')
        monto_pagado = data.get('monto_pagado', 0.0) 
        monto_efectivo_mixto = data.get('monto_efectivo_mixto', 0.0) 
        monto_yape_mixto = data.get('monto_yape_mixto', 0.0)       
        
        if not metodo_pago:
            db.session.rollback() 
            return jsonify({'message': 'Debe seleccionar un método de pago para completar la venta.'}), 400

        # Conversión a float segura
        try:
            monto_pagado_float = float(monto_pagado) if monto_pagado is not None else 0.0
            monto_efectivo_mixto_float = float(monto_efectivo_mixto) if monto_efectivo_mixto is not None else 0.0
            monto_yape_mixto_float = float(monto_yape_mixto) if monto_yape_mixto is not None else 0.0
        except ValueError:
            db.session.rollback() 
            return jsonify({'message': 'Los montos de pago no son números válidos.'}), 400
        
        if not productos_vendidos:
            db.session.rollback() 
            return jsonify({'message': 'No hay productos para vender.'}), 400

        try:
            # 2.1. Validar y calcular el total
            registros_venta = []
            total_venta_calculado = 0.0
            
            for item in productos_vendidos:
                inventario_id = int(item.get('id'))
                cantidad_vendida = int(item.get('cantidad'))
                precio_final = float(item.get('precio_final')) 
                subtotal = precio_final * cantidad_vendida
                total_venta_calculado += subtotal
                
                producto_inventario = Inventario.query.get(inventario_id)
                
                if not producto_inventario or producto_inventario.farmacia_id != farmacia_actual.id:
                    raise Exception("Producto no encontrado o no pertenece a esta sucursal.")
                
                if producto_inventario.stock < cantidad_vendida:
                    raise Exception(f'Stock insuficiente para {producto_inventario.nombre}. Stock disponible: {producto_inventario.stock}')
                
                # Crear el objeto de venta
                nueva_venta = Sale(
                    inventario_id=inventario_id,
                    user_id=current_user.id,
                    farmacia_id=farmacia_actual.id,
                    nombre_producto=producto_inventario.nombre,
                    cantidad=cantidad_vendida,
                    precio_con_descuento=precio_final, 
                    total=subtotal,
                    costo_unitario_venta=producto_inventario.costo_promedio,
                    
                    # Campos de Pago
                    metodo_pago=metodo_pago,
                    monto_pagado=monto_pagado_float,
                    monto_efectivo_mixto=monto_efectivo_mixto_float,
                    monto_yape_mixto=monto_yape_mixto_float
                )
                registros_venta.append((nueva_venta, producto_inventario, cantidad_vendida))
            
            # 2.2. Validar que el monto pagado cubra el total
            # Si el JS falló la validación o fue manipulado
            if monto_pagado_float < round(total_venta_calculado, 2):
                raise Exception(f"El monto pagado ({monto_pagado_float:.2f}) es menor al total de la venta ({total_venta_calculado:.2f}).")

            # 2.3. Ejecutar la transacción
            for venta, producto_inventario, cantidad_vendida in registros_venta:
                db.session.add(venta)
                producto_inventario.stock -= cantidad_vendida # Actualizar stock

            db.session.commit()
            return jsonify({'message': 'Venta procesada con éxito', 'success': True}), 200

        except Exception as e:
            # Rollback en caso de error
            db.session.rollback()
            app.logger.error(f"Error al procesar venta: {e}")
            
            error_message = str(e)
            return jsonify({'message': f'Error al procesar la venta. Detalle: {error_message}'}), 500

    # 3. Lógica GET (Mostrar inventario)
    inventario = Inventario.query.filter_by(farmacia_id=farmacia_actual.id).order_by(Inventario.nombre).all()
    
    # Renderizar la plantilla
    return render_template('pantalla_ventas.html', 
                            farmacia_actual=farmacia_actual,
                            inventario=inventario)


# Endpoint para obtener detalles del producto (usado en ventas)
@app.route('/api/producto/<int:producto_id>')
@login_required
def api_producto_detalle(producto_id):
    producto = Producto.query.get_or_404(producto_id)
    
    # Validar que el producto pertenezca a la farmacia del usuario (o la seleccionada si es Admin)
    if current_user.farmacia_id != producto.farmacia_id:
        if current_user.role != 'Admin':
             return jsonify({'success': False, 'message': 'Acceso denegado.'}), 403

    return jsonify({
        'id': producto.id,
        'nombre': producto.nombre,
        'precio_de_venta': producto.precio_de_venta, 
        'stock': producto.stock
    })



# ... (El resto de tu app.py)

# Helper para manejar la hora de Lima
def now_lima():
    zona_horaria = pytz.timezone('America/Lima')
    return datetime.now(zona_horaria)

# --------------------------------------------------------------------------

@app.route('/mis-ventas', methods=['GET', 'POST'])
@login_required
def mis_ventas():
    # --- CONFIGURACIÓN DE ZONA HORARIA (Lima: UTC-5) ---
    ahora_lima = now_lima()  # Hora actual en Lima (aware datetime)
    today_date = ahora_lima.date()  # Fecha de hoy en Lima
    
    if not current_user.farmacia_id:
        flash('No tienes una farmacia asignada para ver tus ventas.', 'danger')
        return redirect(url_for('dashboard'))

    # Inicializar variables de fecha para el REPORTE GENERAL
    fecha_inicio = None
    fecha_fin = None
    fecha_inicio_str = None
    fecha_fin_str = None
    
    # ---------------------------------------------------------------
    # 1. Lógica de Filtro POST (El usuario selecciona un rango)
    # ---------------------------------------------------------------
    if request.method == 'POST':
        fecha_inicio_str = request.form.get('fecha_inicio')
        fecha_fin_str = request.form.get('fecha_fin')
        
        try:
            # Creamos Naive datetime para el filtro en la DB.
            fecha_inicio_naive = datetime.strptime(fecha_inicio_str, '%Y-%m-%d').replace(hour=0, minute=0, second=0)
            # Aseguramos que la fecha final sea el final del día seleccionado (23:59:59)
            fecha_fin_naive = datetime.strptime(fecha_fin_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
            
            fecha_inicio = fecha_inicio_naive
            fecha_fin = fecha_fin_naive
            
        except (ValueError, TypeError):
            # Si hay error en fechas, pero fue un intento de cierre, continuamos.
            if not request.form.get('cierre_caja'):
                flash('Formato de fecha inválido. Usando el reporte de Hoy.', 'warning')
                # Forzamos la lógica de GET
                fecha_inicio = None 

    # Lógica de Default (GET) o si falla el POST: Mostrar solo las ventas de HOY en Lima
    if fecha_inicio is None:
        # 1. Fecha de inicio: Medianoche de HOY (00:00:00)
        fecha_inicio = datetime.combine(today_date, datetime.min.time())
        
        # 2. Fecha de fin: 23:59:59 del día de HOY. Esto captura TODOS los cierres del día.
        fecha_fin = datetime.combine(today_date, datetime.max.time())
        
        fecha_inicio_str = today_date.strftime('%Y-%m-%d')
        fecha_fin_str = today_date.strftime('%Y-%m-%d')

    # ---------------------------------------------------------------
    # 2. Consultas del Reporte General (Tabla y Total General)
    # ---------------------------------------------------------------
    
    # Query de Ventas para el periodo filtrado (para la tabla principal)
    ventas_base_query = Sale.query.filter(
        Sale.user_id == current_user.id, 
        Sale.farmacia_id == current_user.farmacia_id,
        Sale.fecha_venta >= fecha_inicio,
        Sale.fecha_venta <= fecha_fin
    )
    
    # Total Vendido en el periodo filtrado (para el tfoot)
    total_vendido_periodo = db.session.query(func.sum(Sale.total)).filter(
        Sale.user_id == current_user.id, 
        Sale.farmacia_id == current_user.farmacia_id,
        Sale.fecha_venta >= fecha_inicio,
        Sale.fecha_venta <= fecha_fin
    ).scalar() or 0.0

    # Detalle de Ventas para la tabla
    ventas_filtradas = ventas_base_query.order_by(Sale.fecha_venta.desc()).all()
    
    # Historial de cierres para el rango de fechas seleccionado
    historial_cierres = CierreCaja.query.filter(
        CierreCaja.farmacia_id == current_user.farmacia_id,
        CierreCaja.user_id == current_user.id,
        CierreCaja.fecha_cierre >= fecha_inicio,
        CierreCaja.fecha_cierre <= fecha_fin+ timedelta(days=1),
    ).order_by(CierreCaja.fecha_cierre.desc()).all()
    

    # ---------------------------------------------------------------
    # 3. Cálculos para el CIERRE DE CAJA (Lógica del Turno Abierto)
    # ---------------------------------------------------------------
    
    # a) Obtener el punto de inicio del turno (Desde el último cierre)
    ultimo_cierre = CierreCaja.query.filter(
        CierreCaja.farmacia_id == current_user.farmacia_id,
    ).order_by(CierreCaja.fecha_cierre.desc()).first()
    
    # Si no hay cierre previo, el turno empieza HOY a las 00:00 (Hora de Lima, Naive)
    fecha_inicio_caja_default = datetime.combine(today_date, datetime.min.time()) 
    
    # El turno actual comienza DESPUÉS del último cierre o al inicio del día.
    fecha_inicio_caja = ultimo_cierre.fecha_cierre if ultimo_cierre else fecha_inicio_caja_default
    fecha_fin_caja = ahora_lima.replace(tzinfo=None) # La hora actual es el fin del turno abierto

    # b) Calcular las ventas registradas DEL TURNO ABIERTO (Para el reporte superior y cuadre)
    ventas_turno_abierto = db.session.query(
        func.sum(Sale.total).label('total_vendido'), 
        # 1. EFECTIVO TOTAL
        (func.sum(case((Sale.metodo_pago == 'Efectivo', Sale.total), else_=0)) +
         func.sum(case((Sale.metodo_pago == 'Mixto', Sale.monto_efectivo_mixto), else_=0))
        ).label('efectivo_reg'),
        # 2. NO EFECTIVO (TARJETA/YAPE/TRANSFERENCIA) TOTAL
        (func.sum(case((func.lower(Sale.metodo_pago).in_(['transferencia', 'tarjeta', 'yape']), Sale.total), else_=0)) +
         func.sum(case((Sale.metodo_pago == 'Mixto', Sale.monto_yape_mixto), else_=0))
        ).label('tarjeta_reg')
    ).filter(
        Sale.farmacia_id == current_user.farmacia_id,
        Sale.user_id == current_user.id,
        # FILTRO CLAVE: Ventas solo del turno abierto (desde el último cierre)
        Sale.fecha_venta > fecha_inicio_caja, 
        Sale.fecha_venta <= fecha_fin_caja
    ).first()
    
    
    # 4. CONFIGURACIÓN DE VARIABLES PARA LA VISTA Y CÁLCULOS
    efectivo_reg_turno = ventas_turno_abierto.efectivo_reg or 0.0
    tarjeta_reg_turno = ventas_turno_abierto.tarjeta_reg or 0.0
    total_vendido_turno = ventas_turno_abierto.total_vendido or 0.0
    fondo_fijo_previo = ultimo_cierre.fondo_fijo if ultimo_cierre else 0.0

    diferencia_efectivo_calc = 0.0
    diferencia_tarjeta_calc = 0.0
    
    # 5. Lógica de Cierre de Caja (Guardado en DB)
    if request.method == 'POST' and request.form.get('cierre_caja'):
        try:
            # Montos contados por el usuario
            efectivo_contado_form = float(request.form.get('efectivo_contado'))
            tarjeta_yape_fisico_form = float(request.form.get('tarjeta_yape_fisico'))
            
            # Cálculo de lo que DEBERÍA HABER
            efectivo_esperado = efectivo_reg_turno + fondo_fijo_previo

            # Cálculo de diferencias
            diferencia_efectivo_calc = efectivo_contado_form - efectivo_esperado
            diferencia_tarjeta_calc = tarjeta_yape_fisico_form - tarjeta_reg_turno
            
            # --- GUARDAR EL CIERRE DE CAJA ---
            nuevo_cierre = CierreCaja(
                fecha_cierre=ahora_lima.replace(tzinfo=None), # Naive datetime para la DB
                user_id=current_user.id,
                farmacia_id=current_user.farmacia_id,
                fondo_fijo=fondo_fijo_previo,
                efectivo_sistema=efectivo_reg_turno,
                efectivo_contado=efectivo_contado_form,
                tarjeta_sistema=tarjeta_reg_turno,
                tarjeta_yape_fisico=tarjeta_yape_fisico_form,
                diferencia_efectivo=diferencia_efectivo_calc,
                diferencia_tarjeta=diferencia_tarjeta_calc,
                ventas_totales_sistema=total_vendido_turno 
            )
            db.session.add(nuevo_cierre)
            db.session.commit()
            
            flash('Cierre de caja registrado exitosamente. Las ventas de su turno han sido consolidadas.', 'success')
            return redirect(url_for('mis_ventas')) # Redirigir a GET para limpiar el estado POST
            
        except (ValueError, TypeError, Exception) as e:
            db.session.rollback()
            flash(f'Error al procesar o guardar el cierre de caja. Detalle: {e}', 'danger')


    # 6. Crear el diccionario 'totales_caja_data' para el reporte superior
    totales_caja_data = {
        # Montos Registrados por el Sistema para el TURNO ABIERTO
        'efectivo_sistema': efectivo_reg_turno,
        'tarjeta_sistema': tarjeta_reg_turno,
        'ventas_totales_sistema': total_vendido_turno,
        
        # Fondos y Diferencias (Solo se mostrarán si se hizo un POST de cierre)
        'fondo_caja': fondo_fijo_previo, 
        'diferencia_efectivo': diferencia_efectivo_calc,
        'diferencia_tarjeta': diferencia_tarjeta_calc
    }


    # 7. Renderizado de la Vista
    reporte_nombre = f"Reporte de Ventas de {current_user.username}"
    
    # Lógica para mostrar el rango de fechas en el título
    if fecha_inicio.date() != today_date or fecha_fin.date() != today_date:
        reporte_nombre += f" ({fecha_inicio_str} a {fecha_fin_str})"
    else:
        reporte_nombre += " (Hoy)"


    # --- 4. Renderizado ---

    reporte_nombre = f"Reporte de Ventas de {current_user.username}"
    if request.method == 'POST' or fecha_inicio.date() != today_date:
        if request.method == 'POST':
            display_fecha_fin_str = fecha_fin_str 
        else:
            display_fecha_fin_str = today_date.strftime('%Y-%m-%d')
            
        reporte_nombre += f" ({fecha_inicio_str} a {display_fecha_fin_str})"
    else:
        reporte_nombre += " (Hoy)"


    return render_template('mis_ventas.html',
        reporte_nombre=reporte_nombre,
        fecha_inicio_str=fecha_inicio_str,
        fecha_fin_str=fecha_fin_str, 
        ventas=ventas_filtradas,
        total_vendido_hoy=total_vendido_periodo, # Usamos el nuevo nombre para el total de la tabla
        historial_cierres=historial_cierres,
        totales_caja=totales_caja_data,
        ultimo_cierre=ultimo_cierre
    )

# ----------------------------------------------------
# 7. NUEVOS REPORTES PROFESIONALES (Admin)
# ----------------------------------------------------
# ... (El resto de tus imports, configuración y modelos) ...

@app.route('/reporte-global', methods=['GET', 'POST'])
@login_required
@admin_required
def reporte_global():

    # app.py (Función reporte_global - Reemplazar la sección 1 completa)
    # ===================================================================
    # 1. CAPTURA Y TRATAMIENTO DE FILTROS (CONSOLIDADO Y CORREGIDO)
    # ===================================================================
    
    # Establecer la zona horaria (IMPORTANTE para manejo de fechas)
    tz = pytz.timezone('America/Lima')
    now = datetime.now(tz)
    
    # Captura de filtros
    farmacia_seleccionada_id = request.form.get('farmacia_id', type=int)
    filtro_vendedor = request.form.get('filtro_vendedor')
    fecha_inicio_str = request.form.get('fecha_inicio')
    fecha_fin_str = request.form.get('fecha_fin')
    reporte_hoy = request.form.get('reporte_hoy') # Captura del botón "Reporte del Día"

    # Si es el primer acceso (GET) o si los campos POST estaban vacíos, intenta leer GET
    if not farmacia_seleccionada_id and request.args.get('farmacia_id'):
        farmacia_seleccionada_id = request.args.get('farmacia_id', type=int)

    if not filtro_vendedor and request.args.get('filtro_vendedor'):
        filtro_vendedor = request.args.get('filtro_vendedor')

    # 1.1 Lógica para el botón "Reporte del Día" (Prioridad alta)
    if reporte_hoy == 'true':
        # La fecha de inicio es 00:00:00 del día de hoy
        fecha_inicio = now.replace(hour=0, minute=0, second=0, microsecond=0)
        # La fecha de fin es 23:59:59.999999 del día de hoy
        fecha_fin = now.replace(hour=23, minute=59, second=59, microsecond=999999)
        
        # Actualizamos las strings para el input HTML
        fecha_inicio_str = fecha_inicio.strftime('%Y-%m-%d')
        fecha_fin_str = fecha_fin.strftime('%Y-%m-%d')
        
    # 1.2 Lógica de Fechas Manuales (Si hay strings y no es reporte del día)
    elif fecha_inicio_str and fecha_fin_str:
        try:
            # Convertimos las strings a datetime sin timezone por ahora
            fecha_inicio_date = datetime.strptime(fecha_inicio_str, '%Y-%m-%d')
            fecha_fin_date = datetime.strptime(fecha_fin_str, '%Y-%m-%d')
            
            # Establecer inicio del día (00:00:00) y aplicar timezone
            fecha_inicio = tz.localize(fecha_inicio_date.replace(hour=0, minute=0, second=0, microsecond=0))
            
            # Establecer fin del día (23:59:59.999999) y aplicar timezone
            fecha_fin = tz.localize(fecha_fin_date.replace(hour=23, minute=59, second=59, microsecond=999999))
            
        except ValueError:
            flash('Formato de fecha inválido. Usando mes actual.', 'error')
            # Forzamos la lógica por defecto si hay un error
            fecha_inicio_str = None
            fecha_fin_str = None
            
    # 1.3 Lógica de Fechas por defecto (Mes Actual - Solo se ejecuta si no hay fechas válidas)
    if not fecha_inicio_str or not fecha_fin_str:
        # Calcular el inicio del mes actual (primer día del mes, 00:00:00)
        fecha_inicio = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        # Calcular el último día del mes actual (23:59:59.999999)
        if now.month == 12:
            siguiente_mes = now.replace(year=now.year + 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            siguiente_mes = now.replace(month=now.month + 1, day=1, hour=0, minute=0, second=0, microsecond=0)
            
        fecha_fin = siguiente_mes - timedelta(microseconds=1)
        
        # Formatear para que los inputs HTML muestren el valor correcto
        fecha_inicio_str = fecha_inicio.strftime('%Y-%m-%d')
        fecha_fin_str = fecha_fin.strftime('%Y-%m-%d')

    # --- Filtros de Query (El resto de la función sigue igual, usando fecha_inicio y fecha_fin) ---
    # ...



    # --- Filtros de Query ---
    # 1. Filtro de Farmacia
    ventas_base_query = Sale.query
    if farmacia_seleccionada_id:
        ventas_base_query = ventas_base_query.filter(Sale.farmacia_id == farmacia_seleccionada_id)
        # ... lógica para obtener farmacia_nombre ...
    user_obj = None
    # 2. Filtro de Vendedor (AHORA FILTRA POR USERNAME, NO POR ID, usa el campo del modelo)
    if filtro_vendedor:
        # Debes asegurarte que tu modelo Sale tiene un campo 'vendedor_rel' que te permite
        # acceder al username, o filtrar directamente si el campo 'vendedor' en Sale es el username.
        # Si 'vendedor_rel' existe:
        user_obj = User.query.filter_by(username=filtro_vendedor).first()
        if user_obj:
            ventas_base_query = ventas_base_query.filter(Sale.user_id == user_obj.id)
    
    # 1.1 Filtro por Farmacia
    if farmacia_seleccionada_id:
        ventas_base_query = ventas_base_query.filter(Sale.farmacia_id == farmacia_seleccionada_id)
        farmacia_obj = Farmacia.query.get(farmacia_seleccionada_id)
        farmacia_nombre = farmacia_obj.nombre if farmacia_obj else 'Consolidado Global'
    else:
        farmacia_nombre = 'Consolidado Global'

    # CAMBIO CLAVE 2: Filtro por Vendedor (Usando el ID)
    if user_obj:
        # Filtra directamente por el ID del usuario en la tabla Sale (más robusto)
        ventas_base_query = ventas_base_query.filter(Sale.user_id == user_obj.id)

    # 1.3 Filtro por Fecha (La query está lista para agregaciones)
    ventas_filtradas_query = ventas_base_query.filter(
        Sale.fecha_venta >= fecha_inicio,
        Sale.fecha_venta <= fecha_fin
    )
    
    # ---------------------------------------------------------------
    # --- 2. Cálculos Financieros del Período (Optimizado con DB) ---
    # ---------------------------------------------------------------
    
    # a) Total Vendido y Utilidad Neta (Una sola consulta a la DB)
    # ✅ CORRECCIÓN 2: Uso de .with_entities() para evitar el Producto Cartesiano (SAWarning)
    financial_summary = ventas_filtradas_query.with_entities(
        func.sum(Sale.total).cast(Float).label('total_vendido'),
        func.sum(
            # Utilidad = (Precio Final - Costo Unitario) * Cantidad
            (Sale.precio_con_descuento - Sale.costo_unitario_venta) * Sale.cantidad
        ).cast(Float).label('utilidad_neta_periodo')
    ).first()

    # Manejar el caso de que no haya ventas (los resultados de la suma son None)
    total_vendido = financial_summary.total_vendido or 0.0
    utilidad_neta_periodo = financial_summary.utilidad_neta_periodo or 0.0
    
    # b) Top 10 productos más vendidos (por total de venta) - Otra consulta a la DB
    # ✅ CORRECCIÓN 3: Uso de .with_entities() para evitar el Producto Cartesiano (SAWarning)
    top_10_productos_raw = ventas_filtradas_query.with_entities(
        Sale.nombre_producto,
        func.sum(Sale.total).label('total_producto')
    ).group_by(
        Sale.nombre_producto
    ).order_by(
        func.sum(Sale.total).desc()
    ).limit(10).all()

    # Formatear el resultado: lista de tuplas (nombre_producto, total)
    top_10_productos = [(row.nombre_producto, row.total_producto) for row in top_10_productos_raw]

    # c) Obtener la lista de ventas para la tabla (Historial)
    ventas_filtradas = ventas_filtradas_query.order_by(Sale.fecha_venta.desc()).all() 

    # ---------------------------------------------------------------
    # --- 3. CÁLCULO DE PÉRDIDAS POR AJUSTES DE STOCK ---
    # ---------------------------------------------------------------
    
    # 3.1 Query base para Ajustes de Stock
    ajustes_base_query = AjusteStock.query.filter(
        AjusteStock.fecha_ajuste >= fecha_inicio,
        AjusteStock.fecha_ajuste <= fecha_fin
    )
    
    # 3.2 Filtro por Farmacia
    if farmacia_seleccionada_id:
        # El modelo AjusteStock ahora tiene farmacia_id, no necesitamos unir Inventario aquí
        ajustes_base_query = ajustes_base_query.filter(
            AjusteStock.farmacia_id == farmacia_seleccionada_id
        )
        
    # 3.3 Calcular la suma de las pérdidas valorizadas (Solo tipo 'Pérdida')
    total_perdidas_query_result = ajustes_base_query.with_entities(
        func.sum(
            case(
                # Solo sumar si el movimiento es una Pérdida
                (AjusteStock.tipo_movimiento == 'Pérdida', AjusteStock.diferencia_valorizada),
                else_=0
            )
        ).cast(Float).label('total_perdidas')
    ).scalar()
    
    total_perdidas = total_perdidas_query_result or 0.0

    # ✅ NUEVO CÓDIGO: Obtener el detalle de los ajustes de stock
    # Solo seleccionamos las pérdidas para la tabla de detalle
    detalle_ajustes_perdida = ajustes_base_query.filter(
        AjusteStock.tipo_movimiento == 'Pérdida'
    ).order_by(AjusteStock.fecha_ajuste.desc()).all()
    
    # Prepara el detalle para la plantilla (Necesitamos acceder al nombre del producto)
    ajustes_para_tabla = []
    for ajuste in detalle_ajustes_perdida:
        # Unir el ajuste con el nombre del producto (asumiendo que Inventario está relacionado)
        producto_ajustado = Inventario.query.get(ajuste.inventario_id)
        
        ajustes_para_tabla.append({
            'fecha': ajuste.fecha_ajuste.strftime('%Y-%m-%d %H:%M'),
            'producto': producto_ajustado.nombre if producto_ajustado else 'Producto Desconocido',
            'motivo': ajuste.motivo,
            'cantidad': abs(ajuste.diferencia), # Muestra la cantidad sin signo
            'costo_unitario': ajuste.costo_unitario_ajuste,
            'valor_perdido': ajuste.diferencia_valorizada,
            'vendedor': ajuste.user_rel.username if ajuste.user_rel else 'N/A'
        })
    # --- FIN DEL NUEVO BLOQUE 3 ---
    

    # ---------------------------------------------------------------
    # --- 4. Valorización del Inventario Actual ---
    # ---------------------------------------------------------------
    inventario_query = Inventario.query
    if farmacia_seleccionada_id:
        inventario_query = inventario_query.filter(Inventario.farmacia_id == farmacia_seleccionada_id)
    
    inventario_actual = inventario_query.filter(Inventario.stock > 0).all()

    valor_costo = 0.0 # Valoración al Costo Promedio Ponderado (PMP)
    valor_venta = 0.0 # Valoración al Precio de Venta
    
    inventario_detalle = []
    for item in inventario_actual:
        valor_costo += item.stock * item.costo_promedio
        valor_venta += item.stock * item.precio_de_venta
        
        # Cálculo del porcentaje de utilidad potencial
        if item.costo_promedio > 0:
            porcentaje_utilidad = ((item.precio_de_venta - item.costo_promedio) / item.costo_promedio) * 100
        else:
            porcentaje_utilidad = 100.0 if item.precio_de_venta > 0 else 0.0
            
        inventario_detalle.append({
            'nombre': item.nombre,
            'stock': item.stock,
            'precio_de_venta': item.precio_de_venta,
            'porcentaje_utilidad': porcentaje_utilidad
        })
        
    utilidad_potencial = valor_venta - valor_costo
    
    # Prepara los datos para la tabla de ventas
    ventas_para_tabla = [{
        'fecha_venta': venta.fecha_venta.strftime('%Y-%m-%d %H:%M'),
        'nombre_producto': venta.nombre_producto,
        'cantidad': venta.cantidad,
        'total': f"S/ {venta.total:.2f}",
        'vendedor': venta.vendedor_rel.username if venta.vendedor_rel else 'N/A' # Asumiendo que vendedor_rel existe
    } for venta in ventas_filtradas]

    # Datos para los filtros
    todas_las_farmacias = Farmacia.query.all()
    
    # CAMBIO CLAVE 3: Obtener solo usuarios de la farmacia seleccionada (si aplica)
    users_query = User.query.filter(User.role.in_(['Admin', 'Empleado']))
    if farmacia_seleccionada_id:
        users_query = users_query.filter(User.farmacia_id == farmacia_seleccionada_id)
        
    all_users = users_query.order_by(User.username).all()
    
    # =======================================================
    # 4. CÁLCULO DE CIERRES DE CAJA (CORREGIDO: Se añade JoinedLoad)
    # =======================================================
    # Importar joinedload arriba en tu archivo si no lo tienes:
    # from sqlalchemy.orm import joinedload
    
    # 1. Creamos la query base con carga anticipada (Eager Loading) de las relaciones.
    # Usamos el modelo CierreCaja (el que contiene el detalle de cuadre)
    cierre_query = CierreCaja.query.options(
        joinedload(CierreCaja.user_rel),     # ✅ Modelo: CierreCaja, Relación: user_rel
        joinedload(CierreCaja.farmacia_rel) # ✅ Modelo: CierreCaja, Relación: farmacia_rel
    )

    # 2. Aplicamos filtros de fecha
    # Usamos la columna de fecha correcta del modelo CierreCaja: fecha_cierre
    cierre_query = cierre_query.filter(CierreCaja.fecha_cierre.between(fecha_inicio, fecha_fin))

    # 3. Aplicar filtro de sucursal
    if farmacia_seleccionada_id:
        cierre_query = cierre_query.filter(CierreCaja.farmacia_id == farmacia_seleccionada_id)

    # 4. Aplicar filtro de vendedor
    if filtro_vendedor:
        # Hacemos JOIN explícito para filtrar por el campo 'username' del modelo User
        cierre_query = cierre_query.join(CierreCaja.user_rel).filter(User.username == filtro_vendedor)

    # 5. Calcular el Total Global de Cierre Reportado (Suma del Efectivo Contado + Tarjeta/Yape Contado)
    total_cierre_reportado = cierre_query.with_entities(
        func.sum(CierreCaja.efectivo_contado + CierreCaja.tarjeta_yape_fisico)
    ).scalar() or 0.0

    # 6. Obtener el detalle de cierres para la tabla
    # Usamos la columna de fecha correcta: fecha_cierre
    cierres_detallados = cierre_query.order_by(CierreCaja.fecha_cierre.desc()).all()


    # 6. Obtener el detalle de cierres para la tabla
    # Usamos la columna de fecha correcta: fecha_cierre
    cierres_detallados = cierre_query.order_by(CierreCaja.fecha_cierre.desc()).all()
    
    # =======================================================
    # 4.1 CÁLCULO DE TOTALES PARA LA TABLA DE CIERRES
    # =======================================================
    # Inicializar contadores
    total_reporte_fondo = 0.0
    total_reporte_efectivo_contado = 0.0
    total_reporte_tarjeta_contado = 0.0
    total_reporte_venta_sistema = 0.0
    total_reporte_sf_efectivo = 0.0
    total_reporte_sf_tarjeta = 0.0
    total_reporte_sf_total = 0.0 # Este debe ser la suma de los dos anteriores

    # Iterar sobre los cierres obtenidos y sumar los campos
    for cierre in cierres_detallados:
        total_reporte_fondo += cierre.fondo_fijo
        total_reporte_efectivo_contado += cierre.efectivo_contado
        total_reporte_tarjeta_contado += cierre.tarjeta_yape_fisico
        
        # 1. CORRECCIÓN VENTA SISTEMA: Usar 'ventas_totales_sistema'
        total_reporte_venta_sistema += cierre.ventas_totales_sistema 
        
        # 2. CORRECCIÓN S/F EFECTIVO: Usar 'diferencia_efectivo'
        total_reporte_sf_efectivo += cierre.diferencia_efectivo
        
        # 3. CORRECCIÓN S/F TARJETA: Usar 'diferencia_tarjeta'
        total_reporte_sf_tarjeta += cierre.diferencia_tarjeta
        
        # 4. TOTAL S/F: Suma de los dos campos anteriores para cada fila
        total_reporte_sf_total += cierre.diferencia_efectivo + cierre.diferencia_tarjeta

    # Crear el diccionario de totales para pasarlo a la plantilla
    totales_cierres_reporte = {
        'fondo_fijo': total_reporte_fondo,
        'efectivo_contado': total_reporte_efectivo_contado,
        'tarjeta_contado': total_reporte_tarjeta_contado,
        'venta_sistema': total_reporte_venta_sistema,
        'sf_efectivo': total_reporte_sf_efectivo,
        'sf_tarjeta': total_reporte_sf_tarjeta,
        'sf_total': total_reporte_sf_total # Total final de Sobrantes/Faltantes
    }
    # ---------------------------------------------------------------


    # ---------------------------------------------------------------
    # --- RETURN FINAL COMPLETO (SOLUCIÓN) ---
    # ---------------------------------------------------------------
    return render_template('reporte_global.html',
        farmacia_nombre=farmacia_nombre,
        total_vendido=total_vendido,
        
        # Variables de Utilidad y Costo (Faltaban en el primer return)
        utilidad_neta_periodo=utilidad_neta_periodo,
        total_perdidas=total_perdidas,
        

        # Variables de Detalle e Inventario
        top_10_productos=top_10_productos,
        valor_costo=valor_costo,
        valor_venta=valor_venta,
        utilidad_potencial=utilidad_potencial,
        inventario=inventario_detalle,
        ventas=ventas_para_tabla,
        ajustes_para_tabla=ajustes_para_tabla,
        
        # Variables de Filtro y Estado
        todas_las_farmacias=todas_las_farmacias,
        farmacia_seleccionada_id=farmacia_seleccionada_id,
        all_users=all_users,
        # CAMBIO CLAVE 4: Pasamos el ID del vendedor para mantener la selección
        filtro_vendedor=filtro_vendedor, 
        fecha_inicio_str=fecha_inicio_str,
        fecha_fin_str=fecha_fin_str,

        # NUEVAS VARIABLES DE CIERRE DE CAJA
        total_cierre_reportado=total_cierre_reportado,
        cierres_detallados=cierres_detallados,
        totales_cierres_reporte=totales_cierres_reporte
    )


# ====================================================================================
# ✅ CÓDIGO ACTUALIZADO PARA GESTION-STOCK
# ====================================================================================
@app.route('/gestion-stock', methods=['GET'])
@login_required
@admin_required
def gestion_stock():
    # Intenta obtener la ID de la farmacia desde el parámetro de consulta (query parameter)
    farmacia_id = request.args.get('farmacia_id', type=int)
    
    todas_las_farmacias = Farmacia.query.all()
    
    if not todas_las_farmacias:
        return render_template('gestion_stock.html', 
                               farmacia_nombre='No hay Sucursales', 
                               inventario=[],
                               farmacias_para_selector=[],
                               farmacia_id=None)

    # 1. Determinar la ID de la farmacia a mostrar
    if farmacia_id is None or farmacia_id == 0:
        # Si no se especifica, toma la primera farmacia de la lista por defecto.
        farmacia_id = todas_las_farmacias[0].id

    # 2. Obtener el objeto Farmacia
    farmacia = db.session.get(Farmacia, farmacia_id)
    if not farmacia:
        flash('Sucursal no encontrada.', 'danger')
        # Si la ID no existe, vuelve a la primera por defecto
        farmacia = todas_las_farmacias[0]
        farmacia_id = farmacia.id 
    
    farmacia_nombre = farmacia.nombre
    
    # 3. Obtener el inventario de la farmacia seleccionada
    inventario_actual = Inventario.query.filter_by(farmacia_id=farmacia_id).all() 

    inventario_list = []
    for item in inventario_actual:
        inventario_list.append({
            'id': item.id, 
            'nombre': item.nombre,
            'stock': item.stock,
            'pmp': f"S/ {item.costo_promedio:.2f}",
            'precio_venta': f"S/ {item.precio_de_venta:.2f}"
        })


    return render_template('gestion_stock.html', 
                           farmacia_nombre=farmacia_nombre, 
                           inventario=inventario_list,
                           farmacias_para_selector=todas_las_farmacias,
                           farmacia_id=farmacia_id)
# ====================================================================================

# ----------------------------------------------------
# RUTA PARA EL AJUSTE DE STOCK (CORREGIDA)
# ----------------------------------------------------
@app.route('/ajustar-stock/<int:inventario_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def ajustar_stock(inventario_id):
    # Obtener el producto de inventario
    producto = Inventario.query.get_or_404(inventario_id)
    # Validar que la farmacia exista antes de intentar obtener su nombre
    farmacia = db.session.get(Farmacia, producto.farmacia_id)
    farmacia_nombre = farmacia.nombre if farmacia else 'Desconocida'

    if request.method == 'POST':
        # 1. Obtención de datos y redirección de error centralizada
        nuevo_stock_str = request.form.get('nuevo_stock')
        motivo = request.form.get('motivo', '').strip()
        error_redirect = url_for('ajustar_stock', inventario_id=inventario_id)

        # 2. Validaciones de Formulario
        if not nuevo_stock_str:
            flash('El nuevo stock es obligatorio.', 'danger')
            return redirect(error_redirect)
            
        if not motivo:
            flash('El motivo del ajuste es obligatorio.', 'danger')
            return redirect(error_redirect)
            
        try:
            nuevo_stock = int(nuevo_stock_str)
        except ValueError:
            flash('La cantidad de stock debe ser un número entero válido.', 'danger')
            return redirect(error_redirect)
        
        if nuevo_stock < 0:
            flash('El stock no puede ser negativo.', 'danger')
            return redirect(error_redirect)
            
        # 3. Proceso de Transacción de Base de Datos
        try:
            cantidad_anterior = producto.stock
            diferencia = nuevo_stock - cantidad_anterior
            
            # Si no hay diferencia, no hay ajuste que registrar
            if diferencia == 0:
                flash('El stock ya es el mismo. No se requiere ajuste.', 'info')
                return redirect(url_for('gestion_stock', farmacia_id=producto.farmacia_id))
            
            # ✅ CAMBIO CRÍTICO: Cálculo de la valorización y tipo de movimiento
            costo_unitario_ajuste = producto.costo_promedio
            # Valorización es siempre el valor ABSOLUTO del cambio monetario
            diferencia_valorizada = abs(diferencia) * costo_unitario_ajuste 
            
            if diferencia < 0:
                tipo_movimiento = "Pérdida"
                
                # Se puede agregar una validación adicional si se requiere
                # if nuevo_stock < 0: raise Exception("Stock no puede ser negativo")
                
            else: # diferencia > 0
                tipo_movimiento = "Ganancia" 
                
            # Registrar el Ajuste (Se añadieron los campos faltantes)
            nuevo_ajuste = AjusteStock(
                inventario_id=producto.id,
                user_id=current_user.id,
                farmacia_id=producto.farmacia_id,  # AÑADIDO: Vital para el reporte y la relación
                cantidad_anterior=cantidad_anterior,
                cantidad_ajustada=nuevo_stock,
                diferencia=diferencia,
                motivo=motivo,
                costo_unitario_ajuste=costo_unitario_ajuste,  # AÑADIDO: Costo PMP en el momento del ajuste
                diferencia_valorizada=diferencia_valorizada,  # AÑADIDO: Valor monetario del ajuste
                tipo_movimiento=tipo_movimiento                 # AÑADIDO: Tipo de movimiento ('Pérdida' o 'Ganancia')
            )
            db.session.add(nuevo_ajuste)

            # Actualizar el stock del inventario
            producto.stock = nuevo_stock
            db.session.commit()
            
            flash(f'Stock de "{producto.nombre}" ajustado exitosamente de {cantidad_anterior} a {nuevo_stock}. Diferencia: {diferencia}', 'success')
            return redirect(url_for('gestion_stock', farmacia_id=producto.farmacia_id))

        except Exception as e:
            # Capturar cualquier otro error de base de datos
            flash(f'Error al procesar el ajuste de stock: {str(e)}', 'danger')
            db.session.rollback() # Obligatorio para deshacer cualquier operación de DB
            return redirect(error_redirect)

    # Lógica GET
    return render_template('ajustar_stock.html', 
                           producto=producto, 
                           farmacia_nombre=farmacia_nombre)

# ----------------------------------------------------
# RUTA PARA EL TRASPASO DE STOCK (NUEVA RUTA)
# ----------------------------------------------------
@app.route('/traspaso-stock/<int:inventario_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def traspaso_stock(inventario_id):
    producto_origen = Inventario.query.get_or_404(inventario_id)
    farmacia_origen = Farmacia.query.get(producto_origen.farmacia_id)
    
    # Obtener todas las farmacias excepto la de origen
    farmacias_destino = Farmacia.query.filter(Farmacia.id != farmacia_origen.id).all()
    
    if not farmacias_destino:
        flash('No hay otras sucursales a las que transferir stock.', 'danger')
        return redirect(url_for('gestion_stock', farmacia_id=producto_origen.farmacia_id))

    if request.method == 'POST':
        # --- INICIALIZACIÓN DE VARIABLES CRÍTICAS ---
        valor_movimiento = 0.0 # <--- ¡CLAVE! Inicializamos con un valor por defecto
        costo_unitario = 0.0   # Inicializamos también para seguridad
        # --
        try:
            cantidad_str = request.form.get('cantidad_transferir')
            farmacia_destino_id = request.form.get('farmacia_destino_id')

            if not cantidad_str or not farmacia_destino_id:
                flash('Faltan datos de cantidad o destino.', 'danger')
                return redirect(url_for('traspaso_stock', inventario_id=inventario_id))

            cantidad_transferir = int(cantidad_str)
            farmacia_destino_id = int(farmacia_destino_id)
            
            if cantidad_transferir <= 0:
                flash('La cantidad a transferir debe ser positiva.', 'danger')
                return redirect(url_for('traspaso_stock', inventario_id=inventario_id))

            if producto_origen.stock < cantidad_transferir:
                flash(f'Stock insuficiente. Solo hay {producto_origen.stock} unidades de {producto_origen.nombre}.', 'danger')
                return redirect(url_for('traspaso_stock', inventario_id=inventario_id))

            farmacia_destino = Farmacia.query.get_or_404(farmacia_destino_id)

            # 1. Buscar o Crear el Producto en la Farmacia de Destino
            producto_destino = Inventario.query.filter_by(
                farmacia_id=farmacia_destino_id,
                nombre=producto_origen.nombre
            ).first()

            if not producto_destino:
                # El producto no existe en el destino, se crea con los mismos datos de PMP y Precio de Venta
                producto_destino = Inventario(
                    farmacia_id=farmacia_destino_id,
                    nombre=producto_origen.nombre,
                    stock=0, # Se incrementará luego
                    costo_promedio=producto_origen.costo_promedio,
                    precio_de_venta=producto_origen.precio_de_venta
                )
                db.session.add(producto_destino)
                db.session.flush() # Para que producto_destino tenga ID


            # **********************************************
            # * CORRECCIÓN FINAL: Cálculo de Valorización *
            # **********************************************
            costo_unitario = producto_origen.costo_promedio
            # Asegurar que el costo no sea None si el producto fue creado sin costo
            if costo_unitario is None:
                costo_unitario = 0.0
                
            valor_movimiento = cantidad_transferir * costo_unitario 
            # **********************************************

            # 2. Registrar el Ajuste de Salida (Origen)
            ajuste_salida = AjusteStock(
                inventario_id=producto_origen.id,
                user_id=current_user.id,
                farmacia_id=farmacia_origen.id, # <-- ¡CORREGIDO!
                fecha_ajuste=datetime.now(),
                cantidad_anterior=producto_origen.stock,
                cantidad_ajustada=producto_origen.stock - cantidad_transferir,
                diferencia=-cantidad_transferir,
                costo_unitario_ajuste=costo_unitario,
                diferencia_valorizada=-valor_movimiento, # <-- ¡CLAVE! Asignamos el valor 
                tipo_movimiento='TRASPASO_SALIDA',
                motivo=f'Traspaso de stock a: {farmacia_destino.nombre}'
                
            )
            db.session.add(ajuste_salida)
            
            # 3. Registrar el Ajuste de Entrada (Destino)
            ajuste_entrada = AjusteStock(
                inventario_id=producto_destino.id,
                user_id=current_user.id,
                farmacia_id=farmacia_destino.id, # <-- ¡CORREGIDO!
                fecha_ajuste=datetime.now(),
                cantidad_anterior=producto_destino.stock,
                cantidad_ajustada=producto_destino.stock + cantidad_transferir,
                diferencia=cantidad_transferir,
                costo_unitario_ajuste=costo_unitario,
                diferencia_valorizada=valor_movimiento, # <-- ¡CLAVE! Asignamos el valor POSITIVO
                tipo_movimiento='TRASPASO_ENTRADA',
                motivo=f'Traspaso de stock desde: {farmacia_origen.nombre}'
            )
            db.session.add(ajuste_entrada)
            
            # 4. Actualizar el Stock en ambas ubicaciones
            producto_origen.stock -= cantidad_transferir
            # El PMP y Precio de Venta se mantienen del origen al destino.
            producto_destino.stock += cantidad_transferir 

            db.session.commit()
            
            flash(f'Traspaso exitoso: {cantidad_transferir} unidades de "{producto_origen.nombre}" transferidas de {farmacia_origen.nombre} a {farmacia_destino.nombre}.', 'success')
            return redirect(url_for('gestion_stock', farmacia_id=producto_origen.farmacia_id))

        except ValueError:
            flash('La cantidad a transferir debe ser un número entero válido.', 'danger')
            db.session.rollback()
        except Exception as e:
            flash(f'Error al procesar el traspaso de stock: {str(e)}', 'danger')
            db.session.rollback()


    # Lógica GET
    return render_template('traspaso_stock.html', 
                           producto_origen=producto_origen, 
                           farmacia_origen=farmacia_origen,
                           farmacias_destino=farmacias_destino)

@app.route('/dashboard')
@login_required
def dashboard():
    context = {'user_role': current_user.role}

    if current_user.role == 'Admin':
        today = date.today()
        yesterday = today - timedelta(days=1)
        
        # Ventas totales hoy (Admin)
        total_sales_today = db.session.query(func.sum(Sale.total)).filter(
            Sale.fecha_venta >= datetime(today.year, today.month, today.day)
        ).scalar() or 0.0

        # Ventas totales ayer (Admin)
        total_sales_yesterday = db.session.query(func.sum(Sale.total)).filter(
            Sale.fecha_venta >= datetime(yesterday.year, yesterday.month, yesterday.day),
            Sale.fecha_venta < datetime(today.year, today.month, today.day)
        ).scalar() or 0.0
        
        # Total de Farmacias
        total_farmacias = Farmacia.query.count()
        
        context.update({
            'total_sales_today': f"S/ {total_sales_today:.2f}",
            'total_sales_yesterday': f"S/ {total_sales_yesterday:.2f}",
            'total_farmacias': total_farmacias
        })
        
    return render_template('dashboard.html', **context)

# ----------------------------------------------------
# 8. ENDPOINT API PARA PRECIO ANTERIOR (Compra)
# ----------------------------------------------------
@app.route('/api/get_product_price')
@login_required
def get_product_price():
    """
    Endpoint API para obtener el precio de venta anterior y el PMP
    de un producto específico en una farmacia específica.
    """
    nombre_producto = request.args.get('nombre', type=str)
    farmacia_id = request.args.get('farmacia_id', type=int)

    if not nombre_producto or not farmacia_id:
        # Devuelve 400 si faltan parámetros
        return jsonify({'error': 'Faltan parámetros (nombre o farmacia_id)'}), 400

    # Buscar el producto existente en el inventario de la farmacia
    producto = Inventario.query.filter(
        Inventario.farmacia_id == farmacia_id,
        Inventario.nombre == nombre_producto
    ).first()

    if producto:
        # Si el producto existe, devuelve sus datos relevantes
        return jsonify({
            'exists': True,
            'precio_anterior': producto.precio_de_venta,
            'costo_promedio': producto.costo_promedio,
            'stock': producto.stock
        })
    else:
        # Si el producto es nuevo, devuelve un estado 'False'
        return jsonify({
            'exists': False,
            'precio_anterior': 0.0,
            'costo_promedio': 0.0,
            'stock': 0
        })

# app.py (Nueva Ruta POST)

# ----------------------------------------------------
# RUTA PARA CERRAR LA CAJA (POST)
# ----------------------------------------------------

# app.py (Función cerrar_caja corregida)

@app.route('/cerrar_caja', methods=['POST'])
@login_required
def cerrar_caja():
    """Ruta para guardar de forma definitiva el cierre de caja."""
    if not current_user.farmacia_id:
        flash('No tiene una farmacia asignada para realizar cierres.', 'danger')
        return redirect(url_for('mis_ventas'))

    # --- CONFIGURACIÓN DE ZONA HORARIA (Lima: UTC-5) ---
    zona_horaria = pytz.timezone('America/Lima')
    ahora_lima = datetime.now(zona_horaria)
    cierre_time = ahora_lima.replace(tzinfo=None)
    
    # [LÍNEA ELIMINADA: Se quita la inicialización redundante de fecha_inicio_turno]
    # fecha_inicio_turno = ultimo_cierre.fecha_cierre if ultimo_cierre else datetime(1900, 1, 1) 

    try:
        # 1. Datos ingresados por el usuario
        fondo_fijo = float(request.form.get('fondo_fijo', 0.0)) 
        tarjeta_yape_fisico = float(request.form.get('tarjeta_yape_fisico', 0.0)) 
        efectivo_contado = float(request.form.get('efectivo_contado', 0.0))
        
        # 2. Obtención de fecha_inicio_turno (Inicio del turno = Fecha del último cierre)
        fecha_inicio_caja_default = ahora_lima.replace(hour=0, minute=0, second=0, microsecond=0).replace(tzinfo=None)
        
        # FIX 1: Quitamos el filtro por user_id. Buscamos el último cierre de la FARMACIA.
        ultimo_cierre_anterior = CierreCaja.query.filter(
            CierreCaja.farmacia_id == current_user.farmacia_id
        ).order_by(CierreCaja.fecha_cierre.desc()).first()
        
        # Definimos la fecha de inicio del turno
        fecha_inicio_turno = ultimo_cierre_anterior.fecha_cierre if ultimo_cierre_anterior else fecha_inicio_caja_default

        # 3. Calcular las ventas registradas desde el inicio del turno
        ventas_turno_query = db.session.query(
            func.sum(Sale.total).label('total_vendido'),

            # EFECTIVO ESPERADO (Solo Ventas):
            (func.sum(case((Sale.metodo_pago == 'Efectivo', Sale.total), else_=0)) +
             func.sum(case((Sale.metodo_pago == 'Mixto', Sale.monto_efectivo_mixto), else_=0))
            ).label('efectivo_reg'),

            # NO-EFECTIVO ESPERADO (Solo Ventas):
            (func.sum(case((func.lower(Sale.metodo_pago).in_(['transferencia', 'tarjeta', 'yape']), Sale.total), else_=0)) +
             func.sum(case((Sale.metodo_pago == 'Mixto', Sale.monto_yape_mixto), else_=0))
            ).label('tarjeta_reg')
            
        ).filter(
            Sale.farmacia_id == current_user.farmacia_id,
            # FIX 2: Quitamos el filtro por user_id. Contamos TODAS las ventas de la farmacia desde el último cierre.
            Sale.fecha_venta >= fecha_inicio_turno
        ).first()

        # Extraer los resultados y manejar el caso None (sin ventas)
        if ventas_turno_query:
            total_ventas_sistema = ventas_turno_query.total_vendido or 0.0
            efectivo_esperado_venta = ventas_turno_query.efectivo_reg or 0.0
            tarjeta_yape_esperado = ventas_turno_query.tarjeta_reg or 0.0
        else:
            total_ventas_sistema = 0.0
            efectivo_esperado_venta = 0.0
            tarjeta_yape_esperado = 0.0




        # ------------------------------------------------------------------
        # Se elimina la Lógica de Fusión (3.5.) para siempre crear un nuevo registro
        # ------------------------------------------------------------------

        # 1. BLOQUEO CRÍTICO: No se permite el cierre si no hay ventas.
        if total_ventas_sistema <= 0.0:
            flash('Error: No se puede cerrar la caja sin ventas registradas en este turno.', 'danger')
            return redirect(url_for('mis_ventas'))
        # 4. CÁLCULO DE DIFERENCIAS (Lógica de Cuadre)
        
        # Monto de Efectivo ESPERADO total en la caja = Fondo Fijo + Ventas de Efectivo del Sistema
        # Nota: La diferencia_efectivo original solo se calcula sobre las ventas. 
        # Si deseas que la diferencia sea sobre el efectivo esperado total (Fondo + Ventas), usa:
        # efectivo_esperado_total = fondo_fijo + efectivo_esperado_venta
        # diferencia_efectivo = efectivo_contado - efectivo_esperado_total 
        
        # Mantenemos tu lógica original de solo cuadrar ventas vs contado:
        diferencia_efectivo = efectivo_contado - efectivo_esperado_venta

        # Diferencia Tarjeta = Tarjeta/Yape Contado (Físico) - Tarjeta/Yape Esperado (Sistema)
        diferencia_tarjeta = tarjeta_yape_fisico - tarjeta_yape_esperado
        
        
        # 5. Guardar el registro de Cierre de Caja
        flash_message = '✅ ¡Cierre de caja guardado definitivamente! Nuevo registro creado.'
        # Si cerramos la caja en la ventana de fusión, actualizamos el registro anterior.
        nuevo_cierre = CierreCaja(
                user_id=current_user.id,
                farmacia_id=current_user.farmacia_id,
                fecha_cierre=cierre_time, 
                
                # Montos Contados por el usuario
                fondo_fijo=fondo_fijo,
                tarjeta_yape_fisico=tarjeta_yape_fisico, 
                efectivo_contado=efectivo_contado,
                
                # Montos Registrados por el Sistema (para auditoría)
                ventas_totales_sistema=total_ventas_sistema,
                efectivo_esperado=efectivo_esperado_venta, 
                tarjeta_yape_esperado=tarjeta_yape_esperado,
                
                # Resultados del cuadre
                diferencia_efectivo=diferencia_efectivo,
                diferencia_tarjeta=diferencia_tarjeta,
                
        )

        db.session.add(nuevo_cierre)
        db.session.commit()
            
        flash(flash_message, 'success')
        return redirect(url_for('mis_ventas'))

        
    except (ValueError, TypeError) as e:
        db.session.rollback()
        # Si el error es aquí, es probable que no se pudo convertir el input a float
        flash(f'Error al procesar los montos: Asegúrese de ingresar números válidos. Detalle: {e}', 'danger')
        return redirect(url_for('mis_ventas'))
    except Exception as e:
        db.session.rollback()
        # Este catch capturará cualquier otro error (como si la DB no se regeneró correctamente)
        flash(f'Ocurrió un error inesperado al cerrar la caja. Por favor, revise los logs. Detalle: {e}', 'danger')
        return redirect(url_for('mis_ventas'))

# app.py (Función eliminar_producto corregida)
@app.route('/eliminar_producto/<int:producto_id>', methods=['POST'])
@login_required
@admin_required # Solo Administradores pueden eliminar productos del inventario
def eliminar_producto(producto_id):
    producto = Inventario.query.get_or_404(producto_id)
    
    # Capturamos el ID de la farmacia ANTES de eliminar el objeto
    farmacia_id_redirect = producto.farmacia_id

    # Restricción de seguridad: Solo permite eliminar productos de la farmacia del usuario actual
    if producto.farmacia_id != current_user.farmacia_id:
        flash('Acceso denegado. No puede eliminar productos de otra farmacia.', 'danger')
        
        # ✅ CORRECCIÓN 1: Redirige a 'gestion_stock' con el ID de la farmacia del usuario actual
        return redirect(url_for('gestion_stock', farmacia_id=current_user.farmacia_id)) 

    try:
        # Se elimina el registro de inventario
        db.session.delete(producto)
        db.session.commit()
        flash(f'Producto "{producto.nombre}" eliminado exitosamente del inventario.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error al intentar eliminar el producto: {e}', 'danger')

    # ✅ CORRECCIÓN 2: Redirige a 'gestion_stock' con el ID de la farmacia de donde se eliminó el producto
    return redirect(url_for('gestion_stock', farmacia_id=farmacia_id_redirect))

@app.route('/modificar_precio_venta/<int:inventario_id>', methods=['POST'])
@login_required
def modificar_precio_venta(inventario_id):
    # Asumo que su modelo se llama 'Inventario'
    producto = Inventario.query.get_or_404(inventario_id)
    
    # Valida que el producto pertenezca al usuario/farmacia actual
    # Si tiene implementada la lógica de current_user.farmacia_id, descomente esto:
    # if producto.farmacia_id != current_user.farmacia_id:
    #     flash('Acceso denegado. No puede modificar productos de otra farmacia.', 'danger')
    #     return redirect(url_for('gestion_stock', farmacia_id=current_user.farmacia_id))
    
    nuevo_precio_str = request.form.get('nuevo_precio')
    
    if not nuevo_precio_str:
        flash('El nuevo precio no puede estar vacío.', 'danger')
        return redirect(url_for('gestion_stock', farmacia_id=producto.farmacia_id))

    try:
        # Intenta convertir el valor a un número flotante (decimal)
        nuevo_precio = float(nuevo_precio_str)
        if nuevo_precio < 0:
            flash('El precio no puede ser negativo.', 'danger')
            return redirect(url_for('gestion_stock', farmacia_id=producto.farmacia_id))
            
        # Actualiza el precio de venta y guarda en la base de datos
        producto.precio_venta = nuevo_precio
        db.session.commit()
        
        flash(f'El precio de venta de "{producto.nombre}" fue actualizado a S/. {nuevo_precio:.2f}.', 'success')
        
    except ValueError:
        flash('Valor de precio inválido. Debe ser un número.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al actualizar el precio. Detalle: {e}', 'danger')

    # Redirige a la página de stock con la farmacia actual
    return redirect(url_for('gestion_stock', farmacia_id=producto.farmacia_id))



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)