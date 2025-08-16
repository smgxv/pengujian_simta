# Gunakan golang alpine sebagai base image
FROM golang:1.23.4-alpine

# Set working directory
WORKDIR /app

# Install dependensi sistem yang diperlukan
RUN apk add --no-cache gcc musl-dev

# Copy go mod dan sum files
COPY go.mod go.sum ./

# Download semua dependensi
RUN go mod download

# Copy source code
COPY . .

# Build aplikasi
RUN go build -o main .

# Expose port 8085
EXPOSE 8085

# Command untuk menjalankan aplikasi
CMD ["./main"]