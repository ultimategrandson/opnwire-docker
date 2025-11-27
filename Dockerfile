FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /App

# Copy everything
COPY . ./
# Restore as distinct layers
RUN dotnet restore opnwire-docker.sln
# Build and publish a release
RUN dotnet publish opnwire-docker.sln -o out

# Build runtime image
FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /App
COPY --from=build /App/out .

RUN mkdir -p /App/data

ENTRYPOINT ["dotnet", "OpnWire.Docker.dll"]