package main

import (
	"database/sql"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
)

var (
	db          *sql.DB
	redisClient *redis.Client
)

func main() {
	log.Println("Starting Ingestion Service...")

	// Initialize database connection
	initDB()
	defer db.Close()

	// Initialize Redis connection
	initRedis()
	defer redisClient.Close()

	// Initialize Gin router
	router := gin.Default()

	// Health check endpoint
	router.GET("/health", healthCheck)

	// Ingestion endpoints
	router.POST("/ingest", ingestTraffic)
	router.POST("/ingest/batch", ingestBatchTraffic)

	// Get service port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Ingestion Service running on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func initDB() {
	var err error
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgresql://postgres:postgres@localhost:5432/threat_detector?sslmode=disable"
	}

	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Test connection
	if err = db.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	log.Println("Database connected successfully")
}

func initRedis() {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:     redisURL,
		Password: "", // no password for development
		DB:       0,
	})

	log.Println("Redis connected successfully")
}

func healthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  "healthy",
		"service": "ingestion-service",
		"version": "1.0.0",
	})
}

func ingestTraffic(c *gin.Context) {
	// TODO: Implement traffic ingestion logic
	c.JSON(200, gin.H{
		"message": "Ingestion endpoint - to be implemented",
	})
}

func ingestBatchTraffic(c *gin.Context) {
	// TODO: Implement batch traffic ingestion logic
	c.JSON(200, gin.H{
		"message": "Batch ingestion endpoint - to be implemented",
	})
}
