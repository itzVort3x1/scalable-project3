import time
import random
import json

# Initial coordinates (starting point)
current_coordinates = {
    "latitude": 37.7749,  # Approximate location: San Francisco
    "longitude": -122.4194
}

# Step size per second
STEP_SIZE = 0.0001

# Thresholds for health metrics
THRESHOLDS = {
    "heart_rate": {"min": 60, "max": 100},  # bpm
    "blood_pressure_systolic": {"min": 110, "max": 130},  # mmHg
    "blood_pressure_diastolic": {"min": 70, "max": 90},   # mmHg
    "spo2": {"min": 95, "max": 100},  # percentage
    "temperature": {"min": 36.0, "max": 37.5},  # Celsius
}

def generate_coordinates():
    """Simulate movement by updating latitude and longitude every 5 seconds."""
    global current_coordinates

    # Update latitude and longitude by a cumulative step size for 5 seconds
    delta_lat = random.uniform(-STEP_SIZE * 5, STEP_SIZE * 5)
    delta_lon = random.uniform(-STEP_SIZE * 5, STEP_SIZE * 5)

    current_coordinates["latitude"] += delta_lat
    current_coordinates["longitude"] += delta_lon

    return current_coordinates

def generate_health_metrics():
    """Generate random health metrics."""
    heart_rate = random.randint(50, 120)  # Simulating a possible range including spikes
    blood_pressure = {
        "systolic": random.randint(100, 150),  # Simulating a range for spikes
        "diastolic": random.randint(60, 100),
    }
    spo2 = random.randint(90, 102)  # Simulating potential drops or spikes
    temperature = round(random.uniform(35.0, 39.0), 1)  # Simulating possible fever
    return {
        "heart_rate": heart_rate,
        "blood_pressure": blood_pressure,
        "spo2": spo2,
        "temperature": temperature,
    }

def check_for_spikes(metrics):
    """Check if any health metrics exceed thresholds and log spikes."""
    spikes = []
    if not (THRESHOLDS["heart_rate"]["min"] <= metrics["heart_rate"] <= THRESHOLDS["heart_rate"]["max"]):
        spikes.append(f"Heart rate spike: {metrics['heart_rate']} bpm")
    if not (THRESHOLDS["blood_pressure_systolic"]["min"] <= metrics["blood_pressure"]["systolic"] <= THRESHOLDS["blood_pressure_systolic"]["max"]):
        spikes.append(f"Systolic blood pressure spike: {metrics['blood_pressure']['systolic']} mmHg")
    if not (THRESHOLDS["blood_pressure_diastolic"]["min"] <= metrics["blood_pressure"]["diastolic"] <= THRESHOLDS["blood_pressure_diastolic"]["max"]):
        spikes.append(f"Diastolic blood pressure spike: {metrics['blood_pressure']['diastolic']} mmHg")
    if not (THRESHOLDS["spo2"]["min"] <= metrics["spo2"] <= THRESHOLDS["spo2"]["max"]):
        spikes.append(f"SpO2 spike: {metrics['spo2']}%")
    if not (THRESHOLDS["temperature"]["min"] <= metrics["temperature"] <= THRESHOLDS["temperature"]["max"]):
        spikes.append(f"Temperature spike: {metrics['temperature']} °C")
    return spikes

def mock_smartwatch_data():
    """Mock data from a smartwatch."""
    last_coordinates_time = 0
    last_health_metrics_time = 0

    while True:
        current_time = time.time()

        data = {}

        # Send coordinates every 5 seconds
        if current_time - last_coordinates_time >= 5:
            data["coordinates"] = generate_coordinates()
            last_coordinates_time = current_time

        # Send health metrics every 10 seconds
        if current_time - last_health_metrics_time >= 10:
            health_metrics = generate_health_metrics()
            data["health_metrics"] = health_metrics

            # Check for spikes in health metrics
            spikes = check_for_spikes(health_metrics)
            if spikes:
                print("\nWarning: Health metric spikes detected!")
                for spike in spikes:
                    print(spike)

            last_health_metrics_time = current_time

        if data:  # If there's new data to send
            print(json.dumps(data, indent=2))

        time.sleep(1)  # Check every second

def mock_smartwatch_data_return_str():
    """Mock data from a smartwatch."""
    last_coordinates_time = 0
    last_health_metrics_time = 0

    current_time = time.time()

    data = {}

    # Send coordinates every 5 seconds
    if current_time - last_coordinates_time >= 5:
        data["coordinates"] = generate_coordinates()
        last_coordinates_time = current_time

    # Send health metrics every 10 seconds
    if current_time - last_health_metrics_time >= 10:
        health_metrics = generate_health_metrics()
        data["health_metrics"] = health_metrics

        # Check for spikes in health metrics
        spikes = check_for_spikes(health_metrics)
        if spikes:
            print("\nWarning: Health metric spikes detected!")
            for spike in spikes:
                print(spike)

        last_health_metrics_time = current_time

    if data:  # If there's new data to send
        json_string = json.dumps(data, indent=2)
        return json_string

# Run the mock data generator
if __name__ == "__main__":
    try:
        mock_smartwatch_data()
    except KeyboardInterrupt:
        print("\nStopped smartwatch data generation.")
