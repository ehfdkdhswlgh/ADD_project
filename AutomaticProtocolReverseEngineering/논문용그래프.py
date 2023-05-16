import numpy as np
import matplotlib.pyplot as plt

# Increase the default font size
plt.rcParams.update({'font.size': 15})

protocols = ['UDP', 'TLS', 'GQUIC Q043', 'ARP']
percentages30 = [100, 94.12, 100, 91.67]
percentages60 = [100, 76.47, 100, 83.33]

# The x position of bars
barWidth = 0.4  # Decreased width to increase space between bars
r1 = np.arange(len(protocols))  # the label locations
r2 = [x + barWidth for x in r1]

fig, ax = plt.subplots(figsize=(8, 6))  # Decreased vertical size

bar1 = ax.bar(r1, percentages30, color='darkgray', width=barWidth, edgecolor='grey', label='frequency rate over 30%')
bar2 = ax.bar(r2, percentages60, color='gray', width=barWidth, edgecolor='grey', label='frequency rate over 60%')

# Function to add value labels
def add_labels(bars):
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, height,
                 f'{height}%', ha='center', va='bottom')

add_labels(bar1)
add_labels(bar2)

# Adding labels and title
ax.set_xlabel('Protocols', fontsize=18)
ax.set_ylabel('Percentage (%)', fontsize=18)
ax.set_title('Accuracy of Finding Frequent Sequences Algorithm', y=1.05)
ax.set_xticks([r + barWidth/2 for r in range(len(protocols))])
ax.set_xticklabels(protocols)

# Move legend to the lower right
ax.legend(loc='lower right')
ax.set_ylim(0, 110)
plt.show()
