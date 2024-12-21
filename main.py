"""Аутентификация на основе JWT."""

import datetime

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    status,
)
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

import jwt

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"

TIME_NOW = datetime.datetime.utcnow()
TOKEN_EXPIRATION_DATE_IN_MINUTES = 1


class UserSchema(BaseModel):
    username: str
    password: str


USERS_DATA = [
    UserSchema(**{"username": "user1", "password": "pass1"}),
    UserSchema(**{"username": "user2", "password": "pass2"})
]


def get_user(username: str) -> UserSchema | None:
    """Получение юзера из БД."""
    for user in USERS_DATA:
        if user.username == username:
            return user
    return None


def create_jwt_token(data: dict) -> str:
    """Создание JWT токена."""
    payload = data.copy()
    expiration_time = TIME_NOW + datetime.timedelta(
        minutes=TOKEN_EXPIRATION_DATE_IN_MINUTES
    )

    payload.update({'iat': TIME_NOW, 'exp': expiration_time})

    token = jwt.encode(
        payload=payload,
        key=SECRET_KEY,
        algorithm=ALGORITHM
    )
    return token


def get_user_from_token(token: str = Depends(oauth2_scheme)) -> str:
    """Получение User'а по токену."""
    try:
        payload = jwt.decode(
            jwt=token,
            key=SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        username = payload.get("sub")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            detail='Access Token has expired or expiration date is invalid!',
            status_code=status.HTTP_401_UNAUTHORIZED
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            detail='Invalid Token',
            status_code=status.HTTP_401_UNAUTHORIZED
        )


@app.post("/login")
async def login(user_in: UserSchema):
    """Авторизация."""
    user = get_user(user_in.username)
    if user.password != user_in.password:
        HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {
        "access_token": create_jwt_token(
            {"sub": user_in.username}
        ),
    }


@app.get("/protected_resource")
async def about_me(current_user: str = Depends(get_user_from_token)):
    """Информация о себе."""
    user = get_user(current_user)
    if not user:
        raise HTTPException(
            detail="Invalid credentials",
            status_code=status.HTTP_401_UNAUTHORIZED
        )
    return user
