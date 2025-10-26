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
	log.Println("Starting API Gateway...")

	// Initialize database connection
	initDB()
	defer db.Close()

	// Initialize Redis connection
	initRedis()
	defer redisClient.Close()

	// Initialize Gin router
	router := gin.Default()

	// CORS middleware (allow frontend)
	router.Use(corsMiddleware())

	// Health check (no auth required)
	router.GET("/health", healthCheck)

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Public endpoints (with API key auth)
		v1.Use(apiKeyAuthMiddleware())

		// Alerts
		v1.GET("/alerts", getAlerts)
		v1.GET("/alerts/:id", getAlert)
		v1.PATCH("/alerts/:id", updateAlert)

		// Statistics
		v1.GET("/stats", getStats)
		v1.GET("/stats/daily", getDailyStats)

		// Threats
		v1.GET("/threats", getThreats)
		v1.GET("/threats/:id", getThreat)

		// Analysis
		v1.POST("/analyze", analyzeTraffic)
	}

	// Get service port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	log.Printf("API Gateway running on port %s", port)
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

// Middleware functions
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-API-Key")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, PATCH, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func apiKeyAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")

		// In development, allow a default key
		expectedKey := os.Getenv("API_KEY")
		if expectedKey == "" {
			expectedKey = "dev-api-key-12345"
		}

		if apiKey == "" || apiKey != expectedKey {
			c.JSON(401, gin.H{"error": "Unauthorized - Invalid or missing API key"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Handler functions (stubs for now)
func healthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  "healthy",
		"service": "api-gateway",
		"version": "1.0.0",
	})
}

func getAlerts(c *gin.Context) {
	// TODO: Implement get alerts logic
	c.JSON(200, gin.H{
		"message": "Get alerts endpoint - to be implemented",
		"data":    []interface{}{},
	})
}

func getAlert(c *gin.Context) {
	id := c.Param("id")
	c.JSON(200, gin.H{
		"message": "Get alert by ID endpoint - to be implemented",
		"id":      id,
	})
}

func updateAlert(c *gin.Context) {
	id := c.Param("id")
	c.JSON(200, gin.H{
		"message": "Update alert endpoint - to be implemented",
		"id":      id,
	})
}

func getStats(c *gin.Context) {
	// TODO: Implement get stats logic
	c.JSON(200, gin.H{
		"message": "Get stats endpoint - to be implemented",
		"stats": gin.H{
			"total_threats":   0,
			"total_normal":    0,
			"total_processed": 0,
		},
	})
}

func getDailyStats(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "Get daily stats endpoint - to be implemented",
		"data":    []interface{}{},
	})
}

func getThreats(c *gin.Context) {
	// TODO: Implement get threats logic
	c.JSON(200, gin.H{
		"message": "Get threats endpoint - to be implemented",
		"data":    []interface{}{},
	})
}

func getThreat(c *gin.Context) {
	id := c.Param("id")
	c.JSON(200, gin.H{
		"message": "Get threat by ID endpoint - to be implemented",
		"id":      id,
	})
}

func analyzeTraffic(c *gin.Context) {
	// TODO: Implement analyze traffic logic
	c.JSON(200, gin.H{
		"message": "Analyze traffic endpoint - to be implemented",
	})
}
