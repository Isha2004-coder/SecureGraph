
import streamlit as st
import pandas as pd
import networkx as nx
import plotly.graph_objects as go

st.set_page_config(page_title="SecureGraph", layout="wide")
st.title("SecureGraph: Network Security Visualization Dashboard")

@st.cache_data
def load_data(path="data/network_data.csv"):
    df = pd.read_csv(path)
    return df

df = load_data()

# Sidebar controls
st.sidebar.header("Filters & Controls")
segments = ["All"] + sorted(df['segment'].unique().tolist())
sel_segment = st.sidebar.selectbox("Segment", segments, index=0)
max_latency = int(df['latency_ms'].max())
latency_threshold = st.sidebar.slider("Max latency (ms)", 0, max_latency, max_latency)

show_only_attacks = st.sidebar.checkbox("Show only attack connections", value=False)

# Apply filters
df_filtered = df[df['latency_ms'] <= latency_threshold]
if sel_segment != "All":
    df_filtered = df_filtered[(df_filtered['segment'] == sel_segment) | (df_filtered['segment'] == sel_segment)]
if show_only_attacks:
    df_filtered = df_filtered[df_filtered['attack_flag'] == 1]

# Summary metrics
col1, col2, col3 = st.columns(3)
col1.metric("Total Connections", len(df_filtered))
col2.metric("Average Latency (ms)", round(df_filtered['latency_ms'].mean() if len(df_filtered)>0 else 0, 2))
col3.metric("Attack Attempts", int(df_filtered['attack_flag'].sum()))

# Build NetworkX graph
G = nx.from_pandas_edgelist(df_filtered, 'source', 'destination', ['latency_ms', 'attack_flag', 'segment'])
pos = nx.spring_layout(G, seed=42, k=0.5)

# Prepare edge traces
edge_x, edge_y, edge_colors = [], [], []
for u, v, data in G.edges(data=True):
    x0, y0 = pos[u]
    x1, y1 = pos[v]
    edge_x += [x0, x1, None]
    edge_y += [y0, y1, None]
    edge_colors.append('red' if data.get('attack_flag',0)==1 else '#888')

edge_trace = go.Scatter(
    x=edge_x, y=edge_y,
    line=dict(width=1, color='#888'),
    hoverinfo='none',
    mode='lines')

# Node traces
node_x, node_y, node_text, node_color = [], [], [], []
for node in G.nodes():
    x, y = pos[node]
    node_x.append(x)
    node_y.append(y)
    attacks = df_filtered[(df_filtered['source'] == node) | (df_filtered['destination'] == node)]['attack_flag'].sum()
    latency = df_filtered[(df_filtered['source'] == node) | (df_filtered['destination'] == node)]['latency_ms'].mean()
    node_text.append(f"{node}<br>Avg Latency: {latency:.1f} ms<br>Attack Attempts: {attacks}")
    node_color.append('red' if attacks>0 else 'green')

node_trace = go.Scatter(
    x=node_x, y=node_y,
    mode='markers+text',
    text=list(G.nodes()),
    textposition="top center",
    hoverinfo='text',
    marker=dict(
        showscale=False,
        color=node_color,
        size=22,
        line=dict(width=2, color='white')
    ),
    textfont=dict(size=10)
)

fig = go.Figure(data=[edge_trace, node_trace],
                layout=go.Layout(
                    title="<b>Network Connection Map</b>",
                    title_x=0.5,
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=0, l=0, r=0, t=40),
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                )

st.plotly_chart(fig, use_container_width=True)

# Data and insights
st.subheader("🔍 Network Traffic Data (Filtered)")
st.dataframe(df_filtered.reset_index(drop=True))

st.subheader("📝 Quick Insights")
insights = []
attack_segments = df_filtered[df_filtered['attack_flag']==1]['segment'].unique().tolist()
if len(attack_segments)>0:
    insights.append(f"Attack activity detected in segments: {', '.join(attack_segments)}")
high_latency = df_filtered[df_filtered['latency_ms'] > df_filtered['latency_ms'].mean() + df_filtered['latency_ms'].std() if len(df_filtered)>0 else 0]
if len(high_latency)>0:
    insights.append(f"{len(high_latency)} connections have unusually high latency (possible performance issues).")

if len(insights)==0:
    st.info("No anomalies detected with current filters.")
else:
    for i in insights:
        st.warning(i)
