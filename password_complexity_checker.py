import re
import tkinter as tk
from tkinter import messagebox

def min_length(password, length=8):
    # Check if the password is at least the given length
    return len(password) >= length

def pattern(password, pattern, message):
     # Check if the password contains a specific pattern
    return bool(re.search(pattern, password)), message

def check_password_strength(password):
   # Check the overall strength of the password and provide feedback
    feedback = []

    checks = [
        (min_length(password), "Password should be at least 8 characters long."),
        (pattern(password, r'[A-Z]', "Password should contain at least one uppercase letter.")),
        (pattern(password, r'[a-z]', "Password should contain at least one lowercase letter.")),
        (pattern(password, r'[0-9]', "Password should contain at least one digit.")),
        (pattern(password, r'[@$!%*?&]', "Password should contain at least one special character (@, $, !, %, *, ?, &)."))
    ]

    for check, message in checks:
        if not check:
            feedback.append(message)

    # Determine password strength
    num_conditions_met = 5 - len(feedback)
    if num_conditions_met == 5:
        strength = "Strong password!"
    elif num_conditions_met >= 3:
        strength = "Moderate password."
    else:
        strength = "Weak password."
    
    return strength, feedback

# password strength check and display results in GUI
def check_password():
    password = password_entry.get()
    strength, feedback = check_password_strength(password)
    result_label.config(text=strength)
    
    if feedback:
        suggestions = "Suggestions to improve your password:\n" + "\n".join(f"- {suggestion}" for suggestion in feedback)
        messagebox.showinfo("Password Feedback", suggestions)
    else:
        messagebox.showinfo("Suggestions", "Your password meets all the criteria.")

# GUI
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x300")

tk.Label(root, text="Enter your password:", font=("Arial", 12)).pack(pady=10)
password_entry = tk.Entry(root, show='', font=("Arial", 12), width=30)  # Change show='*' to show=''
password_entry.pack(pady=5)

check_button = tk.Button(root, text="Check Password", command=check_password, font=("Arial", 12), width=20)
check_button.pack(pady=20)

result_label = tk.Label(root, text="", font=("Arial", 12))
result_label.pack(pady=10)

root.mainloop()
