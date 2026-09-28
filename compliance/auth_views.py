"""
Vistas de autenticación y gestión de usuarios
"""
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User, Group
from django.db.models import Q


def login_view(request):
    """Vista de login"""
    
    # Si ya está autenticado, redirigir al dashboard
    if request.user.is_authenticated:
        return redirect('assets_list')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            messages.success(request, f'Bienvenido, {user.get_full_name() or user.username}')
            
            # Redirigir a la página solicitada o al dashboard
            next_url = request.GET.get('next', 'assets_list')
            return redirect(next_url)
        else:
            messages.error(request, 'Usuario o contraseña incorrectos')
    
    return render(request, 'compliance/auth/login.html')


@login_required
def logout_view(request):
    """Vista de logout"""
    logout(request)
    messages.info(request, 'Has cerrado sesión exitosamente')
    return redirect('login')


@login_required
def profile_view(request):
    """Vista de perfil del usuario"""
    
    context = {
        'user': request.user,
        'groups': request.user.groups.all(),
        'is_admin': request.user.is_superuser or request.user.groups.filter(name='Administradores').exists(),
        'is_auditor': request.user.groups.filter(name='Auditores').exists(),
        'is_operator': request.user.groups.filter(name='Operadores').exists(),
    }
    
    return render(request, 'compliance/auth/profile.html', context)


# ============================================================
# DECORADORES DE PERMISOS PERSONALIZADOS
# ============================================================

def admin_required(view_func):
    """Decorador que requiere que el usuario sea administrador"""
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        if not (request.user.is_superuser or request.user.groups.filter(name='Administradores').exists()):
            messages.error(request, 'No tienes permisos para acceder a esta sección')
            return redirect('assets_list')
        
        return view_func(request, *args, **kwargs)
    return wrapper


def operator_or_admin_required(view_func):
    """Decorador que requiere que el usuario sea operador o admin"""
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        if not (request.user.is_superuser or 
                request.user.groups.filter(Q(name='Administradores') | Q(name='Operadores')).exists()):
            messages.error(request, 'No tienes permisos para realizar esta acción')
            return redirect('assets_list')
        
        return view_func(request, *args, **kwargs)
    return wrapper


# ============================================================
# GESTIÓN DE USUARIOS (SOLO ADMIN)
# ============================================================

@admin_required
def users_list(request):
    """Lista de usuarios del sistema"""
    
    users = User.objects.all().prefetch_related('groups')
    
    context = {
        'users': users,
        'page_title': 'Gestión de Usuarios'
    }
    
    return render(request, 'compliance/users/list.html', context)


@admin_required
def user_create(request):
    """Crear nuevo usuario"""
    
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')
        groups = request.POST.getlist('groups')
        
        # Validaciones
        if User.objects.filter(username=username).exists():
            messages.error(request, 'El nombre de usuario ya existe')
        elif password != password_confirm:
            messages.error(request, 'Las contraseñas no coinciden')
        else:
            try:
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name
                )
                
                # Asignar grupos
                for group_id in groups:
                    group = Group.objects.get(id=group_id)
                    user.groups.add(group)
                
                messages.success(request, f'Usuario {username} creado exitosamente')
                return redirect('users_list')
                
            except Exception as e:
                messages.error(request, f'Error al crear usuario: {str(e)}')
    
    # GET request
    groups = Group.objects.all()
    
    context = {
        'groups': groups,
        'page_title': 'Crear Usuario'
    }
    
    return render(request, 'compliance/users/form.html', context)


@admin_required
def user_edit(request, user_id):
    """Editar usuario existente"""
    
    user = User.objects.get(id=user_id)
    
    if request.method == 'POST':
        user.email = request.POST.get('email')
        user.first_name = request.POST.get('first_name')
        user.last_name = request.POST.get('last_name')
        user.is_active = request.POST.get('is_active') == 'on'
        
        # Actualizar contraseña si se proporciona
        new_password = request.POST.get('new_password')
        if new_password:
            password_confirm = request.POST.get('password_confirm')
            if new_password == password_confirm:
                user.set_password(new_password)
            else:
                messages.error(request, 'Las contraseñas no coinciden')
                return redirect('user_edit', user_id=user_id)
        
        # Actualizar grupos
        user.groups.clear()
        groups = request.POST.getlist('groups')
        for group_id in groups:
            group = Group.objects.get(id=group_id)
            user.groups.add(group)
        
        user.save()
        messages.success(request, f'Usuario {user.username} actualizado exitosamente')
        return redirect('users_list')
    
    # GET request
    all_groups = Group.objects.all()
    
    context = {
        'edit_user': user,
        'groups': all_groups,
        'user_groups': user.groups.all(),
        'page_title': f'Editar Usuario: {user.username}'
    }
    
    return render(request, 'compliance/users/form.html', context)