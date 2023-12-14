# load test_data from pickle
import pickle
import json
# test_data = pickle.load(open('kv_cache_openai_embedding.pickle', 'rb'))
# print (list(test_data.values())[0])
# print (list(test_data.values())[1])
from sklearn.manifold import TSNE
from sklearn import preprocessing
from scipy import stats
from sklearn.metrics import silhouette_score
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
from ast import literal_eval
tools = ['mythril', 'slither']
from sklearn.cluster import KMeans
# print (test_data)
from collections import Counter

def extract_tool_embedding(data_file, tool, embedding_type = 'code_embedding'):
    #data_file = 'fp_dict_with_code_with_ir_with_embedding_code_ir.json'
    fp_data = json.load(open(data_file))
    count = 0
    return_data = []
    for key_,val_ in fp_data.items():
        for func_name, func_info in val_.items():
            # print (func_name)
            if embedding_type in func_info and tool in func_info.get('tools', []):
                count = count + 1
                return_data.append(func_info.get(embedding_type))
    print ("found ", count, " functions with ", tool, embedding_type)
    return return_data
# res = extract_tool_embedding('fp_dict_with_code_with_ir_with_embedding_code_ir.json', 'slither', 'ir_embedding')

def plot_tool(tool_name, embedding_type, data_file ):
    data = extract_tool_embedding(data_file, tool_name, embedding_type)

    matrix = np.array(data)
    normalized_matrix =  preprocessing.normalize(matrix)

    if tool_name == 'mythril':
        n_clusters = 5
    elif tool_name == 'gpt_3.5':
        n_clusters = 5
    else:
        n_clusters = 5
    kmeans = KMeans(n_clusters=n_clusters, init="k-means++", random_state=42)
    kmeans.fit(normalized_matrix)
    labels = kmeans.labels_
    cluster_counts = Counter(labels)
    # print ("label data")
    for idx, item in enumerate(labels):
        # print (item)
        if item == 3:
            print (idx)
    # Print out the count of each cluster
    for cluster_id, count in cluster_counts.items():
        print(f"Cluster {cluster_id}: {count} items")

    # Step 1: Compute distances of each point to the centroids
    distances = kmeans.transform(normalized_matrix)

    # Step 2: Find the index of the closest point to each centroid
    closest_points_indices = np.argmin(distances, axis=0)

    # Extract the closest points
    # closest_points = normalized_matrix[closest_points_indices]
    print ("closest points ")
    print (closest_points_indices)
    print("data shape", matrix.shape)
    # print("data sample", matrix[:2][:5])
    # tsne = TSNE(n_components=2,metric="cosine", random_state=42, init="random")
    tsne = TSNE(n_components=2, perplexity=10,metric="cosine", random_state=42, init="random", learning_rate=200)
    vis_dims2 = tsne.fit_transform(matrix)
    x = [x for x, y in vis_dims2]
    y = [y for x, y in vis_dims2]
    print ("max min x idx ",np.argmax(x), np.argmin(x))
    print ("max min x val ",np.max(x), np.min(x))
    print ("max min y idx ",np.argmax(y), np.argmin(y))
    print ("max min y val ",np.max(y), np.min(y))
    plt.clf()
    plt.figure(figsize=(4*1.618,4))
    colormap = plt.cm.get_cmap('viridis', n_clusters)  # Replace 'viridis' with any other colormap if needed
    for category in range(n_clusters):
        color = colormap(category)
        # Correct the filtering here
        xs = np.array(x)[labels == category]
        ys = np.array(y)[labels == category]
        plt.scatter(xs, ys, color=color, alpha=0.3)

        if len(xs) > 0:
            avg_x = xs.mean()
            avg_y = ys.mean()
            plt.scatter(avg_x, avg_y, marker="x", color=color, s=100)

    # plt.title("Clusters visualization with t-SNE")
    plt.savefig(f"{tool_name}_{embedding_type}_cluster.pdf")
    return closest_points_indices

plot_tool('gpt_3.5', 'code_embedding', "merged_fp_all_tools.json")
plot_tool('slither', 'code_embedding', "merged_fp_all_tools.json")
plot_tool('mythril', 'code_embedding', "merged_fp_all_tools.json")

