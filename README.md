# user-service

## Entorno de desarrollo

Antes de levantar la aplicación es necesario tener las variables de entorno configuradas.
Para hacerlo, se puede copiar el template `.env.example` con el siguiente comando:

```bash
cp .env.example .env
```

> ![IMPORTANT]
>
> Para testear algunos features de producción (aquellos que requieren API keys o credenciales), deberás solicitarlas al equipo de desarrollo.

## Levantar la aplicación

Para levantar el docker compose (servicio de usuarios y base de datos), ejecutar

```bash
docker compose -f docker-compose.yaml up
```

## Tests

Todos los tests se pueden ejecutar con

```bash
docker compose -f docker-compose-test.yaml up
```

Esto ejecuta tanto los test de integración (servicio + db) como los tests unitarios.

## API

La documentación de la API está disponible en el formato especificado según OpenAPI en el archivo [docs/swagger.yaml](./docs/swagger.yaml).
