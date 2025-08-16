FROM golang:1.23.4-alpine

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache gcc musl-dev

# Copy go.mod dan go.sum
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Salin semua source code
COPY . .

# Build aplikasi
RUN go build -o main .

# Buat folder uploads agar bisa digunakan menyimpan file notifikasi
RUN mkdir -p /app/uploads && \
    chmod -R 777 /app/uploads

# Expose port untuk container
EXPOSE 8088

# Jalankan binary
CMD ["./main"]
