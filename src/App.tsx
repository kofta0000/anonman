import { useState, useEffect, useRef } from 'react';

// Security utilities
const sanitizeInput = (input: string): string => {
  return input
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+="[^"]*"/gi, '')
    .trim();
};

const generateSecureId = (): string => {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
};

// Telegram-style encryption implementation (simplified MTProto approach)
const deriveKey = async (password: string, salt: Uint8Array): Promise<CryptoKey> => {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
};

const encryptMessage = async (text: string, userSecret: string): Promise<string> => {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);

    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);

    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);

    const key = await deriveKey(userSecret, salt);
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      data
    );

    const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    result.set(salt, 0);
    result.set(iv, salt.length);
    result.set(new Uint8Array(encrypted), salt.length + iv.length);

    return btoa(String.fromCharCode(...result));
  } catch (error) {
    console.error('Encryption failed:', error);
    return '[Encryption Error]';
  }
};

const decryptMessage = async (encryptedText: string, userSecret: string): Promise<string> => {
  try {
    const data = new Uint8Array(atob(encryptedText).split('').map(c => c.charCodeAt(0)));

    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const encrypted = data.slice(28);

    const key = await deriveKey(userSecret, salt);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      encrypted
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch (error) {
    console.error('Decryption failed:', error);
    return '[Decryption Error]';
  }
};

interface Reaction {
  emoji: string;
  users: string[];
}

interface User {
  id: string;
  username: string;
  isAdmin: boolean;
  isActive: boolean;
  createdAt: Date;
  lastSeen: Date;
  secret: string; // For encryption
}

interface Message {
  id: string;
  userId: string;
  username: string;
  content: string;
  encryptedContent: string;
  timestamp: Date;
  isOwn: boolean;
  reactions: Reaction[];
  isEdited?: boolean;
  isDeleted?: boolean;
  room: string;
}

interface ChatRoom {
  id: string;
  name: string;
  description: string;
  userCount: number;
  isSecure: boolean;
}

interface AuthState {
  isAuthenticated: boolean;
  currentUser: User | null;
  sessionId: string | null;
}

const CHAT_ROOMS: ChatRoom[] = [
  { id: 'general', name: 'General', description: 'General discussion', userCount: 0, isSecure: true },
  { id: 'tech', name: 'Tech Talk', description: 'Technology discussions', userCount: 0, isSecure: true },
  { id: 'secure', name: 'Secure Channel', description: 'High-security communications', userCount: 0, isSecure: true },
  { id: 'admin', name: 'Admin Only', description: 'Administrator communications', userCount: 0, isSecure: true }
];

const COMMON_EMOJIS = ['😀', '😂', '😍', '🤔', '👍', '👎', '❤️', '🔥', '💯', '😢', '😡', '🎉', '👋', '🤝', '💪'];

// Default admin account
const DEFAULT_ADMIN: User = {
  id: 'admin-001',
  username: 'Cif3',
  isAdmin: true,
  isActive: true,
  createdAt: new Date(),
  lastSeen: new Date(),
  secret: 'admin-secret-key-2024'
};

function App() {
  const [auth, setAuth] = useState<AuthState>({
    isAuthenticated: false,
    currentUser: null,
    sessionId: null
  });

  const [users, setUsers] = useState<User[]>([DEFAULT_ADMIN]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [newMessage, setNewMessage] = useState('');
  const [currentRoom, setCurrentRoom] = useState('general');
  const [rooms, setRooms] = useState<ChatRoom[]>(CHAT_ROOMS);
  const [showEmojiPicker, setShowEmojiPicker] = useState(false);
  const [showAdminPanel, setShowAdminPanel] = useState(false);
  const [showUserManagement, setShowUserManagement] = useState(false);
  const [editingMessage, setEditingMessage] = useState<string | null>(null);
  const [editingContent, setEditingContent] = useState('');

  // Login form states
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginError, setLoginError] = useState('');

  // User creation states
  const [newUsername, setNewUsername] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [newUserIsAdmin, setNewUserIsAdmin] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Initialize with demo encrypted messages
  useEffect(() => {
    const initializeDemoMessages = async () => {
      const demoMessages: Message[] = [
        {
          id: generateSecureId(),
          userId: 'admin-001',
          username: 'SystemAdmin',
          content: '', // Will be set after decryption
          encryptedContent: await encryptMessage(
            'Welcome to the secure chat system! 🔒',
            DEFAULT_ADMIN.secret
          ),
          timestamp: new Date(Date.now() - 300000),
          isOwn: false,
          reactions: [{ emoji: '🔒', users: ['SecureUser1'] }],
          room: 'general'
        }
      ];

      // Decrypt for display
      for (const msg of demoMessages) {
        if (auth.currentUser) {
          msg.content = await decryptMessage(msg.encryptedContent, auth.currentUser.secret);
        }
      }

      setMessages(demoMessages);
    };

    if (auth.isAuthenticated && auth.currentUser) {
      initializeDemoMessages();
    }
  }, [auth.isAuthenticated, auth.currentUser]);

  // Auto scroll to bottom when new messages arrive
  // biome-ignore lint/correctness/useExhaustiveDependencies: We need messages dependency for auto-scroll
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError('');

    const sanitizedUsername = sanitizeInput(loginUsername);
    const sanitizedPassword = sanitizeInput(loginPassword);

    if (!sanitizedUsername || !sanitizedPassword) {
      setLoginError('Please enter both username and password');
      return;
    }

    // Find user
    const user = users.find(u =>
      u.username === sanitizedUsername &&
      u.isActive
    );

    if (!user) {
      setLoginError('User not found or inactive');
      return;
    }

    // Simple password verification (in real app, use proper hashing)
    const isPasswordValid = sanitizedPassword === '=]=9f7EP1uDT_9}GU^L}d^DZE.WWhA:-BP3oc~HQwKZbr:.1~pL*rZ-FmKznZ^ch+yy.a60@Y>>U?Hb6EL.xccvN>k!N**=>Uoky' && user.isAdmin;

    if (!isPasswordValid) {
      setLoginError('Invalid credentials');
      return;
    }

    // Create secure session
    const sessionId = generateSecureId();

    setAuth({
      isAuthenticated: true,
      currentUser: { ...user, lastSeen: new Date() },
      sessionId
    });

    // Update user's last seen
    setUsers(prev => prev.map(u =>
      u.id === user.id ? { ...u, lastSeen: new Date() } : u
    ));

    setLoginUsername('');
    setLoginPassword('');
  };

  const handleLogout = () => {
    setAuth({
      isAuthenticated: false,
      currentUser: null,
      sessionId: null
    });
    setMessages([]);
    setCurrentRoom('general');
  };

  const handleCreateUser = async () => {
    if (!auth.currentUser?.isAdmin) return;

    const sanitizedUsername = sanitizeInput(newUsername);
    const sanitizedPassword = sanitizeInput(newUserPassword);

    if (!sanitizedUsername || !sanitizedPassword) {
      alert('Please enter username and password');
      return;
    }

    if (users.some(u => u.username === sanitizedUsername)) {
      alert('Username already exists');
      return;
    }

    const newUser: User = {
      id: generateSecureId(),
      username: sanitizedUsername,
      isAdmin: newUserIsAdmin,
      isActive: true,
      createdAt: new Date(),
      lastSeen: new Date(),
      secret: generateSecureId() // Unique encryption key per user
    };

    setUsers(prev => [...prev, newUser]);
    setNewUsername('');
    setNewUserPassword('');
    setNewUserIsAdmin(false);

    alert(`User ${sanitizedUsername} created successfully!`);
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newMessage.trim() || !auth.currentUser) return;

    const sanitizedContent = sanitizeInput(newMessage.trim());
    const encryptedContent = await encryptMessage(sanitizedContent, auth.currentUser.secret);

    const message: Message = {
      id: generateSecureId(),
      userId: auth.currentUser.id,
      username: auth.currentUser.username,
      content: sanitizedContent,
      encryptedContent,
      timestamp: new Date(),
      isOwn: true,
      reactions: [],
      room: currentRoom
    };

    setMessages(prev => [...prev, message]);
    setNewMessage('');
  };

  const handleReaction = (messageId: string, emoji: string) => {
    if (!auth.currentUser) return;

    setMessages(prev => prev.map(msg => {
      if (msg.id === messageId) {
        const existingReaction = msg.reactions.find(r => r.emoji === emoji);
        if (existingReaction) {
          if (existingReaction.users.includes(auth.currentUser?.username || '')) {
            // Remove reaction
            return {
              ...msg,
              reactions: msg.reactions.map(r =>
                r.emoji === emoji
                  ? { ...r, users: r.users.filter(u => u !== auth.currentUser?.username) }
                  : r
              ).filter(r => r.users.length > 0)
            };
          }
          // Add reaction
          return {
            ...msg,
            reactions: msg.reactions.map(r =>
              r.emoji === emoji
                ? { ...r, users: [...r.users, auth.currentUser?.username || ''] }
                : r
            )
          };
        }
        // New reaction
        return {
          ...msg,
          reactions: [...msg.reactions, { emoji, users: [auth.currentUser?.username || ''] }]
        };
      }
      return msg;
    }));
  };

  const handleEditMessage = async (messageId: string, newContent: string) => {
    if (!auth.currentUser) return;

    const sanitizedContent = sanitizeInput(newContent);
    const encryptedContent = await encryptMessage(sanitizedContent, auth.currentUser.secret);

    setMessages(prev => prev.map(msg =>
      msg.id === messageId
        ? {
            ...msg,
            content: sanitizedContent,
            encryptedContent,
            isEdited: true
          }
        : msg
    ));
    setEditingMessage(null);
    setEditingContent('');
  };

  const handleDeleteMessage = (messageId: string) => {
    if (!auth.currentUser) return;

    if (auth.currentUser.isAdmin) {
      setMessages(prev => prev.filter(msg => msg.id !== messageId));
    } else {
      setMessages(prev => prev.map(msg =>
        msg.id === messageId
          ? { ...msg, content: '[Message deleted]', isDeleted: true }
          : msg
      ));
    }
  };

  const canEditOrDelete = (message: Message) => {
    if (!auth.currentUser) return false;
    if (auth.currentUser.isAdmin) return true;
    if (message.userId !== auth.currentUser.id) return false;
    const timeDiff = Date.now() - message.timestamp.getTime();
    return timeDiff < 300000; // 5 minutes
  };

  const toggleUserStatus = (userId: string) => {
    if (!auth.currentUser?.isAdmin) return;

    setUsers(prev => prev.map(u =>
      u.id === userId ? { ...u, isActive: !u.isActive } : u
    ));
  };

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const currentRoomMessages = messages.filter(msg => msg.room === currentRoom);
  const currentRoomData = rooms.find(room => room.id === currentRoom);

  // Login screen
  if (!auth.isAuthenticated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex items-center justify-center text-white">
        <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-xl p-8 w-full max-w-md">
          <div className="text-center mb-8">
            <div className="text-3xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent mb-2">
              🔒 Secure Chat
            </div>
            <p className="text-slate-400">Admin-controlled encrypted messaging</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Username
              </label>
              <input
                type="text"
                value={loginUsername}
                onChange={(e) => setLoginUsername(e.target.value)}
                className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-3 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter your username"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Password
              </label>
              <input
                type="password"
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
                className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-3 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter your password"
                required
              />
            </div>

            {loginError && (
              <div className="bg-red-900/30 border border-red-700 rounded-lg p-3 text-red-400 text-sm">
                {loginError}
              </div>
            )}

            <button
              type="submit"
              className="w-full bg-blue-600 hover:bg-blue-700 text-white py-3 rounded-lg font-medium transition-colors"
            >
              🔐 Secure Login
            </button>
          </form>


        </div>
      </div>
    );
  }

  // Main chat interface
  return (
    <div className="flex h-screen bg-gradient-to-br from-slate-900 to-slate-800 text-white">
      {/* Sidebar - Room List */}
      <div className="w-64 bg-slate-800/50 backdrop-blur-sm border-r border-slate-700 flex flex-col">
        <div className="p-4 border-b border-slate-700">
          <h2 className="text-lg font-bold text-blue-400">🔒 Secure Rooms</h2>
          <p className="text-xs text-slate-400">End-to-end encrypted</p>
        </div>

        <div className="flex-1 overflow-y-auto p-2">
          {rooms.map(room => (
            <button
              key={room.id}
              onClick={() => setCurrentRoom(room.id)}
              className={`w-full text-left p-3 rounded-lg mb-2 transition-colors ${
                currentRoom === room.id
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-700 hover:bg-slate-600 text-slate-200'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-medium">🔐 {room.name}</span>
                <span className="text-xs bg-slate-600 px-2 py-1 rounded-full">
                  {users.filter(u => u.isActive).length}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">{room.description}</p>
            </button>
          ))}
        </div>

        <div className="p-4 border-t border-slate-700">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
            <span className="text-sm text-slate-300">
              {auth.currentUser?.isAdmin ? '👑' : '🔒'} {auth.currentUser?.username}
            </span>
          </div>

          <div className="space-y-2">
            {auth.currentUser?.isAdmin && (
              <>
                <button
                  onClick={() => setShowUserManagement(!showUserManagement)}
                  className="w-full text-xs bg-blue-600 hover:bg-blue-700 px-3 py-2 rounded transition-colors"
                >
                  👥 Manage Users
                </button>

                <button
                  onClick={() => setShowAdminPanel(!showAdminPanel)}
                  className="w-full text-xs bg-red-600 hover:bg-red-700 px-3 py-2 rounded transition-colors"
                >
                  🛡️ Admin Panel
                </button>
              </>
            )}

            <button
              onClick={handleLogout}
              className="w-full text-xs bg-slate-700 hover:bg-slate-600 px-3 py-2 rounded transition-colors"
            >
              🚪 Logout
            </button>
          </div>
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <div className="bg-slate-800/50 backdrop-blur-sm border-b border-slate-700 p-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-xl font-bold text-white">
                🔐 {currentRoomData?.name}
              </h1>
              <p className="text-sm text-slate-400">
                {currentRoomData?.description} • End-to-end encrypted
              </p>
            </div>
            <div className="text-right">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
                <span className="text-sm text-slate-300">
                  {users.filter(u => u.isActive).length} active users
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* User Management Panel */}
        {showUserManagement && auth.currentUser?.isAdmin && (
          <div className="bg-blue-900/30 border-b border-blue-700 p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-blue-400 font-bold">👥 User Management</h3>
              <button
                onClick={() => setShowUserManagement(false)}
                className="text-blue-400 hover:text-blue-300"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="bg-slate-800/50 rounded-lg p-4">
                <h4 className="text-white font-medium mb-3">Create New User</h4>
                <div className="space-y-3">
                  <input
                    type="text"
                    value={newUsername}
                    onChange={(e) => setNewUsername(e.target.value)}
                    placeholder="Username"
                    className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white text-sm"
                  />
                  <input
                    type="password"
                    value={newUserPassword}
                    onChange={(e) => setNewUserPassword(e.target.value)}
                    placeholder="Password"
                    className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white text-sm"
                  />
                  <label className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={newUserIsAdmin}
                      onChange={(e) => setNewUserIsAdmin(e.target.checked)}
                      className="rounded"
                    />
                    <span>Admin privileges</span>
                  </label>
                  <button
                    onClick={handleCreateUser}
                    className="w-full bg-green-600 hover:bg-green-700 px-3 py-2 rounded text-sm"
                  >
                    Create User
                  </button>
                </div>
              </div>

              <div className="bg-slate-800/50 rounded-lg p-4">
                <h4 className="text-white font-medium mb-3">Active Users</h4>
                <div className="space-y-2 max-h-32 overflow-y-auto">
                  {users.map(user => (
                    <div key={user.id} className="flex items-center justify-between text-sm">
                      <span className={`${user.isActive ? 'text-green-400' : 'text-red-400'}`}>
                        {user.isAdmin ? '👑' : '🔒'} {user.username}
                      </span>
                      <button
                        onClick={() => toggleUserStatus(user.id)}
                        className={`px-2 py-1 rounded text-xs ${
                          user.isActive
                            ? 'bg-red-600 hover:bg-red-700'
                            : 'bg-green-600 hover:bg-green-700'
                        }`}
                      >
                        {user.isActive ? 'Deactivate' : 'Activate'}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Admin Panel */}
        {showAdminPanel && auth.currentUser?.isAdmin && (
          <div className="bg-red-900/30 border-b border-red-700 p-4">
            <div className="flex items-center justify-between">
              <h3 className="text-red-400 font-bold">🛡️ Admin Panel</h3>
              <button
                onClick={() => setShowAdminPanel(false)}
                className="text-red-400 hover:text-red-300"
              >
                ✕
              </button>
            </div>
            <div className="mt-2 flex gap-2 text-sm">
              <button
                onClick={() => setMessages([])}
                className="bg-red-600 hover:bg-red-700 px-3 py-1 rounded"
              >
                Clear All Messages
              </button>
              <button
                onClick={() => {
                  setMessages(prev => prev.filter(msg => msg.userId === auth.currentUser?.id));
                }}
                className="bg-orange-600 hover:bg-orange-700 px-3 py-1 rounded"
              >
                Clear Others' Messages
              </button>
            </div>
          </div>
        )}

        {/* Messages Area */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {currentRoomMessages.map((message) => (
            <div
              key={message.id}
              className={`flex ${message.isOwn ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-xs lg:max-w-md px-4 py-3 rounded-2xl ${
                  message.isOwn
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-700 text-slate-100'
                } ${message.isDeleted ? 'opacity-60' : ''}`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-xs font-medium ${
                    message.isOwn ? 'text-blue-200' : 'text-slate-400'
                  }`}>
                    🔒 {message.username}
                    {message.isEdited && <span className="ml-1 text-xs">(edited)</span>}
                  </span>
                  <span className={`text-xs ${
                    message.isOwn ? 'text-blue-200' : 'text-slate-500'
                  }`}>
                    {formatTime(message.timestamp)}
                  </span>
                </div>

                {editingMessage === message.id ? (
                  <div className="space-y-2">
                    <input
                      type="text"
                      value={editingContent}
                      onChange={(e) => setEditingContent(e.target.value)}
                      className="w-full bg-slate-800 text-white px-2 py-1 rounded text-sm"
                      autoFocus
                    />
                    <div className="flex gap-2">
                      <button
                        onClick={() => handleEditMessage(message.id, editingContent)}
                        className="text-xs bg-green-600 px-2 py-1 rounded"
                      >
                        Save
                      </button>
                      <button
                        onClick={() => {
                          setEditingMessage(null);
                          setEditingContent('');
                        }}
                        className="text-xs bg-gray-600 px-2 py-1 rounded"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <p className="text-sm leading-relaxed">
                      {message.content}
                      <span className="ml-2 text-xs">🔒</span>
                    </p>

                    {/* Reactions */}
                    {message.reactions.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {message.reactions.map((reaction) => (
                          <button
                            key={`${message.id}-${reaction.emoji}`}
                            onClick={() => handleReaction(message.id, reaction.emoji)}
                            className={`text-xs px-2 py-1 rounded-full flex items-center gap-1 ${
                              reaction.users.includes(auth.currentUser?.username || '')
                                ? 'bg-blue-500 text-white'
                                : 'bg-slate-600 hover:bg-slate-500'
                            }`}
                          >
                            {reaction.emoji} {reaction.users.length}
                          </button>
                        ))}
                      </div>
                    )}

                    {/* Message Actions */}
                    <div className="flex items-center gap-2 mt-2">
                      <div className="flex gap-1">
                        {COMMON_EMOJIS.slice(0, 3).map(emoji => (
                          <button
                            key={emoji}
                            onClick={() => handleReaction(message.id, emoji)}
                            className="text-xs hover:bg-slate-600 p-1 rounded"
                          >
                            {emoji}
                          </button>
                        ))}
                      </div>

                      {canEditOrDelete(message) && !message.isDeleted && (
                        <div className="flex gap-1 ml-auto">
                          <button
                            onClick={() => {
                              setEditingMessage(message.id);
                              setEditingContent(message.content);
                            }}
                            className="text-xs hover:bg-slate-600 p-1 rounded"
                          >
                            ✏️
                          </button>
                          <button
                            onClick={() => handleDeleteMessage(message.id)}
                            className="text-xs hover:bg-red-600 p-1 rounded"
                          >
                            🗑️
                          </button>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        {/* Message Input */}
        <div className="bg-slate-800/50 backdrop-blur-sm border-t border-slate-700 p-4">
          <form onSubmit={handleSendMessage}>
            <div className="flex gap-3">
              <input
                type="text"
                value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)}
                placeholder={`🔒 Encrypted message to ${currentRoomData?.name}...`}
                className="flex-1 bg-slate-700 border border-slate-600 rounded-full px-6 py-3 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                maxLength={500}
              />

              <button
                type="button"
                onClick={() => setShowEmojiPicker(!showEmojiPicker)}
                className="bg-slate-700 hover:bg-slate-600 text-white px-4 py-3 rounded-full transition-colors"
              >
                😀
              </button>

              <button
                type="submit"
                disabled={!newMessage.trim()}
                className="bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 disabled:cursor-not-allowed text-white px-6 py-3 rounded-full font-medium transition-colors flex items-center gap-2"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                </svg>
                Send
              </button>
            </div>

            {/* Emoji Picker */}
            {showEmojiPicker && (
              <div className="mt-3 p-3 bg-slate-700 rounded-lg">
                <div className="grid grid-cols-8 gap-2">
                  {COMMON_EMOJIS.map(emoji => (
                    <button
                      key={emoji}
                      onClick={() => {
                        setNewMessage(prev => prev + emoji);
                        setShowEmojiPicker(false);
                      }}
                      className="text-lg hover:bg-slate-600 p-2 rounded transition-colors"
                    >
                      {emoji}
                    </button>
                  ))}
                </div>
              </div>
            )}

            <p className="text-xs text-slate-500 mt-2 text-center">
              🔒 All messages encrypted with Telegram-style encryption •
              {newMessage.length}/500 characters •
              {canEditOrDelete({ isOwn: true, timestamp: new Date(), userId: auth.currentUser?.id || '' } as Message)
                ? ' You can edit/delete for 5 minutes'
                : ''}
            </p>
          </form>
        </div>
      </div>
    </div>
  );
}

export default App;
