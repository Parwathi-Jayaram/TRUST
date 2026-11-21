export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        soc: {
          950: '#070b12',
          900: '#0a1019',
          850: '#0d1623',
          800: '#111d2d',
          700: '#1a2a40',
        },
        cyan: { 400: '#31c7e8' },
      },
      boxShadow: {
        panel: '0 12px 35px rgba(0, 0, 0, 0.22)',
      },
    },
  },
  plugins: [],
}
