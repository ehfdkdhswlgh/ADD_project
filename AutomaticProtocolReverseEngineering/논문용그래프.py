import numpy as np
import matplotlib.pyplot as plt

# Increase the default font size
plt.rcParams.update({'font.size': 19})

protocols = ['TCP', 'ARP', 'ICMP']
accuracies = [66.67, 61.54, 57.89]

# The x position of bars
r1 = np.arange(len(protocols))  # the label locations

fig, ax = plt.subplots(figsize=(8, 6))  # Decreased vertical size

# A thinner bar for reduced gap between bars
# Here, we add a width parameter to make the bars thinner
bar1 = ax.bar(r1, accuracies, width=0.6, color='darkgray', edgecolor='grey')

# Function to add value labels
def add_labels(bars):
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, height,
                 f'{height}%', ha='center', va='bottom')

add_labels(bar1)

# Adding labels and title
ax.set_xlabel('Protocols', fontsize=25)
ax.set_ylabel('Accuracy (%)', fontsize=25)
ax.set_title('Accuracy of hierarchical clustering', y=1.05)
ax.set_xticks(r1)
ax.set_xticklabels(protocols)

# Removed legend
ax.set_ylim(0, 110)
plt.show()
