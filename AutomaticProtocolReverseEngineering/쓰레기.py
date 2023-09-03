import matplotlib.pyplot as plt

# Data
snr = [-10, -5, 0, 5, 10, 20]
accuracy = [40.69, 51.06, 84.81, 100, 100, 100]

# Plot configuration
plt.figure(figsize=(10, 6))
plt.plot(snr, accuracy, marker='o', linestyle='-', color='black')  # Line color changed to black
plt.title('Accuracy per SNR')
plt.xlabel('SNR (dB)')
plt.ylabel('Accuracy (%)')
plt.grid(True, which='both', linestyle='--', linewidth=0.5)
plt.xticks(snr)
plt.yticks(range(0, 110, 10))

# Display the plot
plt.tight_layout()
plt.show()