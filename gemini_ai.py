import google.generativeai as genai

# OPTIONAL: keep API key if available
genai.configure(api_key="AIzaSyDPK2Kzm92ZfcRqPG7k5CyqP6Alyixq-aY")

try:
    model = genai.GenerativeModel("gemini-pro")
except Exception:
    model = None


def gemini_classify(email_text):
    if model is None:
        return "UNAVAILABLE"

    try:
        prompt = f"""
Classify this email into one category:
- phishing
- promotional
- otp
- business

Email:
{email_text}

Return only the category.
"""
        response = model.generate_content(prompt)
        return response.text.strip().lower()
    except Exception as e:
        print("⚠️ Gemini failed:", e)
        return "UNAVAILABLE"
