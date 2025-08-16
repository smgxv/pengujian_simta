# Gunakan versi golang yang lebih stabil
FROM golang:1.23.4-alpine

WORKDIR /app

# Copy go.mod dan go.sum terlebih dahulu
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy seluruh source code
COPY . .

# Build aplikasi
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

EXPOSE 8086

CMD ["./main"]