# Frontend Dockerfile
FROM nginx:alpine

# Copy the HTML file to nginx html directory
COPY public/index.html /usr/share/nginx/html/index.html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port
EXPOSE 3000

# Start nginx
CMD ["nginx", "-g", "daemon off;"]