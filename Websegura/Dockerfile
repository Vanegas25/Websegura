# Estructura de compilación con el SDK de .NET 8.0 o superior
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env
WORKDIR /app

# Copiar archivos del proyecto usando el nombre exacto de tu carpeta
COPY Websegura/*.csproj ./
RUN dotnet restore

# Copiar todo lo demás y compilar
COPY Websegura/ ./
RUN dotnet publish -c Release -o out

# Crear la imagen final de ejecución con el Runtime de .NET 8.0 (El que usa tu proyecto)
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build-env /app/out .

# Configurar el puerto dinámico para Render
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "Websegura.dll"]