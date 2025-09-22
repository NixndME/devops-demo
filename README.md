
# St. Joseph's College - DevOps & Kubernetes Demo App

This is a comprehensive demo application designed to showcase modern DevOps practices, including CI/CD, containerization with Docker, and orchestration with Kubernetes. The application is a Python Flask web server with advanced features for user tracking and real-time analytics.

## Key Features

- **Flask Web Server**: A robust backend serving multiple API endpoints.
- **Advanced User Tracking**: Gathers and displays information about visitors, including:
  - IP Address
  - Geolocation (Country, City, ISP)
  - Device Information (OS, Browser, Device Type)
  - Unique Device Fingerprinting
- **Real-time Analytics**: Provides live statistics on user activity.
- **Prometheus Metrics**: Exposes detailed metrics for monitoring with Prometheus.
- **Containerized**: Fully containerized using Docker for consistent deployments.
- **Kubernetes-Ready**: Includes all necessary Kubernetes manifests for deployment.
- **CI/CD Pipeline**: Integrated with GitHub Actions for automated building, testing, and deployment.
- **High-Performance & Resilient**:
    - Asynchronous handling of geolocation lookups.
    - Rate limiting to prevent abuse.
    - Graceful shutdown mechanism.
    - Comprehensive logging.

## Technology Stack

- **Backend**: Python, Flask
- **Containerization**: Docker
- **Orchestration**: Kubernetes
- **CI/CD**: GitHub Actions
- **Monitoring**: Prometheus

## How to Run Locally

You can run the application locally using Docker Compose.

1.  **Prerequisites**:
    - Docker installed
    - Docker Compose installed

2.  **Run the application**:
    ```bash
    docker-compose up --build
    ```

3.  The application will be available at [http://localhost:5000](http://localhost:5000).

## Available API Endpoints

| Method | Endpoint         | Description                                                                                              |
|--------|------------------|----------------------------------------------------------------------------------------------------------|
| `GET`  | `/`              | The main HTML page of the application.                                                                   |
| `GET`  | `/info`          | Returns a JSON object with application version, deployment time, and details about the current user.     |
| `GET`  | `/analytics`     | Provides a JSON object with real-time analytics, including active sessions and visitor statistics.         |
| `GET`  | `/demo-stats`    | An HTML page displaying live statistics about all active user sessions.                                  |
| `GET`  | `/metrics`       | Exposes Prometheus metrics for monitoring.                                                               |
| `GET`  | `/health`        | A lightweight health check endpoint for Kubernetes liveness probes. Returns `200 OK` if the app is healthy. |
| `GET`  | `/readiness`     | A readiness probe for Kubernetes to check if the app is ready to serve traffic.                          |

## Configuration

The application can be configured using the following environment variables:

| Variable              | Description                                        | Default                  |
|-----------------------|----------------------------------------------------|--------------------------|
| `APP_VERSION`         | The version of the application.                    | `v1.0.12`                |
| `LOG_LEVEL`           | The logging level.                                 | `INFO`                   |
| `DEMO_MODE`           | The demo mode.                                     | `devops-kubernetes`      |
| `ENHANCED_TRACKING`   | Enable or disable enhanced user tracking.          | `true`                   |
| `GEOLOCATION_ENABLED` | Enable or disable geolocation lookups.             | `true`                   |
| `GEOLOCATION_TIMEOUT` | Timeout in seconds for geolocation API calls.      | `2.0`                    |
| `MAX_WORKERS`         | Maximum number of threads for async operations.    | `8`                      |
| `RATE_LIMIT_ENABLED`  | Enable or disable rate limiting.                   | `true`                   |

## CI/CD Pipeline

The project uses GitHub Actions for its CI/CD pipeline, defined in `.github/workflows/ci-cd.yaml`. The pipeline automates the following processes:
- **Linting and Security Scanning**: Checks the code for quality and vulnerabilities.
- **Building Docker Image**: Builds the application's Docker image.
- **Pushing to Registry**: Pushes the image to a container registry.
- **(Placeholder) Deployment**: Contains placeholders for deploying to a Kubernetes cluster.

## Kubernetes Deployment

The `k8s/` directory contains all the necessary Kubernetes manifests for deploying the application, including:
- `deployment.yaml`: Manages the application pods.
- `service.yaml`: Exposes the application as a network service.
- `ingress.yaml`: Manages external access to the anetwork service.
- `configmap.yaml`: For application configuration.
- `hpa.yaml`: Horizontal Pod Autoscaler for automatic scaling.

These manifests are designed to be applied to a Kubernetes cluster to run the application at scale.
