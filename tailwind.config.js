/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'media',
  content: ['./src/**/*.{html,js,svelte,ts}'],
  theme: {
    extend: {
      colors: {
        'canvas': 'rgb(var(--color-canvas) / <alpha-value>)',
        'surface': 'rgb(var(--color-surface) / <alpha-value>)',
        'subtle': 'rgb(var(--color-subtle) / <alpha-value>)',
        'muted': 'rgb(var(--color-muted) / <alpha-value>)',
        'placeholder': 'rgb(var(--color-placeholder) / <alpha-value>)',
        'foreground': 'rgb(var(--color-foreground) / <alpha-value>)',
        'body': 'rgb(var(--color-body) / <alpha-value>)',
        'line': 'rgb(var(--color-line) / <alpha-value>)',
        'strong': 'rgb(var(--color-strong) / <alpha-value>)',
        'accent': 'rgb(var(--color-accent) / <alpha-value>)',
        'info': 'rgb(var(--color-info) / <alpha-value>)',
        'danger': 'rgb(var(--color-danger) / <alpha-value>)',
        'success': 'rgb(var(--color-success) / <alpha-value>)',
        'warning': 'rgb(var(--color-warning) / <alpha-value>)',
        'accent-soft': 'rgb(var(--color-accent-soft) / <alpha-value>)',
        'info-soft': 'rgb(var(--color-info-soft) / <alpha-value>)',
        'danger-soft': 'rgb(var(--color-danger-soft) / <alpha-value>)',
        'success-soft': 'rgb(var(--color-success-soft) / <alpha-value>)',
        'warning-soft': 'rgb(var(--color-warning-soft) / <alpha-value>)',
        'muted-foreground': 'rgb(var(--color-muted-foreground) / <alpha-value>)',
      },
    },
  },
  plugins: [],
}

