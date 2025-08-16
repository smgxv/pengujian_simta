FROM golang:1.23.4-alpine
# FROM golang:1.21-alpine

WORKDIR /app

# Install required system packages
RUN apk add --no-cache gcc musl-dev


# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN go build -o main .

# Create uploads directory with proper permissions
RUN mkdir -p /app/uploads/proposal && \
    chmod -R 777 /app/uploads

# Expose port 8082
EXPOSE 8087

# Command to run the application
CMD ["./main"]