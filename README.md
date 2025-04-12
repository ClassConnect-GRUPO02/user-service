# user-service

## Levantar servicio

Antes de levantar el servicio es necesario tener un archivo `.env` con las variables de entorno necesarias. 
Se provee un archivo de ejemplo que se puede copiar con

```bash
cp .env.example .env
```

Para levantar el docker compose (servicio de usuarios y base de datos), ejecutar

```bash
docker compose up
```

## Tests unitarios

Para ejecutar los tests unitarios, ejecutar

```bash
make test
```
