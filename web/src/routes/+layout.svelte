<script>
  let { children } = $props();
</script>

{@render children()}

<style>
  :global(*) {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  :global(:root) {
    --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;

    --bg-primary: #0a0a0a;
    --bg-secondary: #121212;
    --bg-tertiary: #1a1a1a;

    --text-primary: #ffffff;
    --text-secondary: #a0a0a0;
    --text-muted: #666666;

    --border: #2a2a2a;
    --accent: #4a9eff;
    --error: #ff4a4a;
  }

  :global(body) {
    font-family: var(--font-sans);
    background: var(--bg-primary);
    color: var(--text-primary);
    min-height: 100vh;
  }
</style>
