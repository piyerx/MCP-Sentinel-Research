# benign_server.py
"""
Benign MCP Weather Server

This server provides a clean, non-malicious implementation of the weather tool.
Use this as a baseline for comparison against the malicious server.
"""
from mcp.server.fastmcp import FastMCP

# Create a clean MCP server
mcp = FastMCP("CleanWeatherService")


@mcp.tool()
def get_weather(city: str) -> str:
    """
    Returns the current weather for a specified city.
    
    Args:
        city: The name of the city to get weather information for.
    
    Returns:
        A string containing the current weather conditions.
    """
    # Simulated weather data
    weather_data = {
        "new york": "18°C, partly cloudy",
        "london": "12°C, rainy",
        "tokyo": "22°C, sunny",
        "paris": "15°C, overcast",
        "sydney": "26°C, clear",
    }
    
    city_lower = city.lower()
    if city_lower in weather_data:
        return f"The weather in {city} is {weather_data[city_lower]}."
    else:
        return f"The weather in {city} is 20°C and partly cloudy."


@mcp.tool()
def get_forecast(city: str, days: int = 3) -> str:
    """
    Returns the weather forecast for a specified city.
    
    Args:
        city: The name of the city to get forecast for.
        days: Number of days for the forecast (default: 3).
    
    Returns:
        A string containing the weather forecast.
    """
    return f"Weather forecast for {city} for the next {days} days: Mostly sunny with temperatures between 18-24°C."


@mcp.tool()
def get_temperature(city: str, unit: str = "celsius") -> str:
    """
    Returns the current temperature for a specified city.
    
    Args:
        city: The name of the city.
        unit: Temperature unit - 'celsius' or 'fahrenheit' (default: celsius).
    
    Returns:
        The current temperature.
    """
    temp_c = 22
    if unit.lower() == "fahrenheit":
        temp_f = (temp_c * 9/5) + 32
        return f"The temperature in {city} is {temp_f}°F."
    return f"The temperature in {city} is {temp_c}°C."


if __name__ == "__main__":
    print("Starting Clean Weather Service on default MCP transport...")
    print("This is a BENIGN server with no malicious payloads.")
    mcp.run()
