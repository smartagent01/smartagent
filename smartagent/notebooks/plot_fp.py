import matplotlib.pyplot as plt

# Data series and labels
data_series = [13, 7, 24, 9]
labels = ["Basic-GPT3.5", "SmartAgent-3.5", "Basic-GPT4", "SmartAgent-4"]

plt.figure(figsize=(1.618*4, 4))
colormap = plt.cm.get_cmap('Set2', len(data_series))
bars = plt.bar(labels, data_series,width=0.4, color=colormap.colors)



# Making the plot more formal for academic standards
plt.title("False Positive Reduction", fontsize=14)
plt.xlabel("Aggregation Method", fontsize=12)
plt.ylabel("Number of False Positives", fontsize=12)
plt.xticks(fontsize=10)
plt.yticks(fontsize=10)

# Adding a grid for better readability
plt.grid(axis='y', linestyle='--', alpha=0.7)

# Saving the plot to a PDF file
plt.savefig('false_positive.pdf', format='pdf')
# Saving the plot to a PDF file
# plt.savefig('false_positive.pdf', format='pdf', bbox_inches='tight')

# plt.show()