// Get stored data
let storedToken = localStorage.getItem('jwtToken');
let storedUsername = localStorage.getItem('username');

// Set the username in the HTML
const usernameElement = document.getElementById('username');
if (usernameElement) {
  usernameElement.textContent = storedUsername;
}

// Load page and event listeners
document.addEventListener('DOMContentLoaded', () => {
  const baseUrl = window.location.origin;
  console.log('Base URL:', baseUrl);  // Log base URL to verify it

  fetchPosts(baseUrl);

  if (storedToken) {
    const storedRole = localStorage.getItem('userRole');
    if (storedRole == 'admin') {
      showAdminFeatures();
    }
  }

  const form = document.getElementById('new-post-form');
  if (form) {
    form.addEventListener('submit', (event) => createPost(event, baseUrl));
  }

  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', (event) => loginUser(event, baseUrl));
  }

  const registerForm = document.getElementById('register-form');
  if (registerForm) {
    registerForm.addEventListener('submit', (event) => registerUser(event, baseUrl));
  }
});

// Post details
const postDetailContainer = document.getElementById('post-detail-container');

// Add a listener for detail page
window.addEventListener('load', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const postId = urlParams.get('post');
  if (postId) {
    showPostDetail(postId);
  }
});

// Fetch posts
async function fetchPosts(baseUrl) {
  try {
    const res = await fetch(`${baseUrl}/posts`);
    const data = await res.json();
    const postsList = document.getElementById('posts-list');
    const isAdmin = localStorage.getItem('userRole') === 'admin';

    if (postsList) {
      postsList.innerHTML = data
        .map((post, index) => {
          const deleteButtonStyle = isAdmin ? '' : 'display: none';
          const updateButtonStyle = isAdmin ? '' : 'display: none';

          return `
            <div id="${post._id}" class="post">
              <img src="${post.imageUrl}" alt="Image" />
              <div class="post-title">
                ${
                  index === 0
                    ? `<h1><a href="/post/${post._id}">${post.title}</a></h1>`
                    : `<h3><a href="/post/${post._id}">${post.title}</a></h3>`
                }
              </div>
              ${
                index === 0
                  ? `<span><p>${post.author}</p><p>${post.timestamp}</p></span>`
                  : ''
              }
              <div id="admin-buttons">
                <button class="btn" style="${deleteButtonStyle}" onclick="deletePost('${post._id}', '${baseUrl}')">Delete</button>
                <button class="btn" style="${updateButtonStyle}" onclick="showUpdateForm('${post._id}', '${post.title}', '${post.content}')">Update</button>
              </div>
              ${index === 0 ? '<hr>' : ''}
              ${index === 0 ? '<h2>All Articles</h2>' : ''}
            </div>
          `;
        })
        .join('');
    } else {
      console.log("Empty");
    }
  } catch (error) {
    console.error('Error fetching posts:', error);
  }
}

async function createPost(event, baseUrl) {
  event.preventDefault();
  const titleInput = document.getElementById('title');
  const contentInput = document.getElementById('content');
  const imageUrlInput = document.getElementById('image-url');

  const title = titleInput.value;
  const content = contentInput.value;
  const imageUrl = imageUrlInput.value;

  if (!title || !content || !imageUrl) {
    alert('Please fill in all fields.');
    return;
  }

  const newPost = {
    title,
    content,
    imageUrl,
    author: storedUsername,
    timestamp: new Date().toLocaleDateString(undefined, {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    }),
  };

  try {
    const response = await fetch(`${baseUrl}/posts`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${storedToken}`,
      },
      body: JSON.stringify(newPost),
    });

    if (response.ok) {
      titleInput.value = '';
      contentInput.value = '';
      imageUrlInput.value = '';
      alert('Post created successfully!');
    } else {
      alert('Failed to create post.');
    }
  } catch (error) {
    console.error('Error creating post:', error);
    alert('Failed to create post.');
  }
  fetchPosts(baseUrl);
}

// Delete Post
async function deletePost(postId, baseUrl) {
  try {
    const response = await fetch(`${baseUrl}/posts/${postId}`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${storedToken}`,
      },
    });

    if (response.ok) {
      alert('Post deleted successfully!');
      fetchPosts(baseUrl);
    } else {
      alert('Failed to delete post.');
    }
  } catch (error) {
    console.error('Error deleting post:', error);
    alert('Failed to delete post.');
  }
}

// Update form
function showUpdateForm(postId, title, content) {
  const updateForm = `
    <form id="update-form">
      <input type="text" id="update-title" value="${title}" />
      <textarea id="update-content">${content}</textarea>
      <button type="submit">Update post</button>
    </form>
  `;

  const postElement = document.getElementById(postId);
  postElement.innerHTML += updateForm;

  const form = document.getElementById('update-form');
  form.addEventListener('submit', (event) => updatePost(event, postId));
}

// Update post
async function updatePost(event, postId) {
  event.preventDefault();
  const title = document.getElementById('update-title').value;
  const content = document.getElementById('update-content').value;
  const baseUrl = window.location.origin;

  if (!title || !content) {
    alert('Please fill in all fields.');
    return;
  }

  const updatedPost = { title, content };

  try {
    const response = await fetch(`${baseUrl}/posts/${postId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${storedToken}`,
      },
      body: JSON.stringify(updatedPost),
    });

    if (response.ok) {
      alert('Post updated successfully!');
      fetchPosts(baseUrl);
    } else {
      alert('Failed to update post.');
    }
  } catch (error) {
    console.error('Error updating post:', error);
    alert('Failed to update post.');
  }
}

// Register user
async function registerUser(event, baseUrl) {
  event.preventDefault();
  const usernameInput = document.getElementById('register-username');
  const passwordInput = document.getElementById('register-password');
  const roleInput = document.getElementById('register-role');

  const username = usernameInput.value;
  const password = passwordInput.value;
  const role = roleInput.value;

  if (!username || !password || !role) {
    alert('Please fill in all fields.');
    return;
  }

  const newUser = { username, password, role };

  try {
    const res = await fetch('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newUser),
    });

    const data = await res.json();
    if (data.success) {
      alert('Registration successful!');
      usernameInput.value = '';
      passwordInput.value = '';
      roleInput.value = '';
    } else {
      alert('Registration failed.');
    }
  } catch (error) {
    console.error('Error registering user:', error);
    alert('Registration failed.');
  }
}

// Login user
async function loginUser(event, baseUrl) {
  event.preventDefault();
  const usernameInput = document.getElementById('login-username');
  const passwordInput = document.getElementById('login-password');

  const username = usernameInput.value;
  const password = passwordInput.value;

  if (!username || !password) {
    alert('Please fill in all fields.');
    return;
  }

  const user = { username, password };

  try {
    const res = await fetch(`${baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(user),
    });

    const data = await res.json();
    if (data.success) {
      localStorage.setItem('jwtToken', data.token);
      localStorage.setItem('userRole', data.role);
      localStorage.setItem('username', username);

      location.reload();

      if (data.role === 'admin') {
        showAdminFeatures();
      }
    } else {
      alert('Login failed.');
    }
  } catch (error) {
    console.error('Error logging in:', error);
    alert('Login failed.');
  }
}

// Admin features
function showAdminFeatures() {
  const newPostDiv = document.getElementById('new-post-div');
  if (newPostDiv) {
    newPostDiv.style.display = 'flex';
  }

  const allBtns = document.querySelectorAll('.btn');
  allBtns.forEach((btn) => {
    if (btn) {
      btn.style.display = 'block';
    }
  });
}

// Logout
document.addEventListener('DOMContentLoaded', () => {
  const registerDiv = document.getElementById('register-div');
  const loginDiv = document.getElementById('login-div');
  const logoutDiv = document.getElementById('logout-div');
  const logoutButton = document.getElementById('logout-button');

  if (storedToken) {
    registerDiv.style.display = 'none';
    loginDiv.style.display = 'none';
    logoutDiv.style.display = 'flex';
    logoutButton.addEventListener('click', () => {
      localStorage.removeItem('jwtToken');
      localStorage.removeItem('userRole');
      localStorage.removeItem('username');
      location.reload();
    });
  } else {
    registerDiv.style.display = 'flex';
    loginDiv.style.display = 'flex';
    logoutDiv.style.display = 'none';
  }
});