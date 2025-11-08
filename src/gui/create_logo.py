"""Create Davenport University logo placeholder."""

from PIL import Image, ImageDraw, ImageFont
import os


def create_davenport_logo():
    """Create a Davenport University logo."""
    # Create image
    img = Image.new("RGB", (200, 200), color=(248, 249, 250))  # Light gray background
    draw = ImageDraw.Draw(img)

    # Draw a simple shield shape (Davenport-inspired)
    # Shield outline
    shield_points = [
        (100, 30),  # Top point
        (160, 50),  # Top right
        (160, 110),  # Right side
        (100, 150),  # Bottom
        (40, 110),  # Left side
        (40, 50),  # Top left
    ]

    # Draw shield with red color
    draw.polygon(shield_points, fill="#C8102E", outline="#1F1F1F")

    # Draw inner white stripe
    inner_points = [
        (100, 45),
        (150, 60),
        (150, 105),
        (100, 140),
        (50, 105),
        (50, 60),
    ]
    draw.polygon(inner_points, fill="#FFFFFF", outline="#C8102E")

    # Draw "D" for Davenport
    draw.text((85, 70), "D", fill="#C8102E", font=None)

    # Save logo
    logo_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "assets", "davenport_logo.png"
    )
    os.makedirs(os.path.dirname(logo_path), exist_ok=True)
    img.save(logo_path)
    return logo_path


if __name__ == "__main__":
    create_davenport_logo()
    print("Logo created successfully!")
