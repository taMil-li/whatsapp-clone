import React, { useState, useEffect, useRef } from "react";
import io from "socket.io-client";
import axios from "axios";
import "./App.css";

const CURRENT_USER_ID = parseInt(prompt("UserID: ")); // Represents 'Alice'
const OTHER_USER_ID = parseInt(prompt("To UserID: ")); // Represents 'Bob'
const OTHER_USER_NAME = CURRENT_USER_ID === 1 ? "Bob" : "Alice";

const socket = io("http://localhost:3001");

function App() {
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState("");
  const messagesEndRef = useRef(null);

  // Effect for fetching initial messages and setting up socket listeners
  useEffect(() => {
    // Register this user with the server
    socket.emit("register", CURRENT_USER_ID);

    // Fetch message history
    axios
      .get(`http://localhost:3001/messages/${CURRENT_USER_ID}/${OTHER_USER_ID}`)
      .then((response) => {
        setMessages(response.data);
      });

    // Listen for incoming messages
    socket.on("receiveMessage", (message) => {
      setMessages((prev) => [...prev, message]);
    });

    // Clean up the socket listener when the component unmounts
    return () => {
      socket.off("receiveMessage");
    };
  }, []);

  // Effect for auto-scrolling to the latest message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSendMessage = (e) => {
    e.preventDefault();
    if (newMessage.trim() === "") return;

    const messageData = {
      sender_id: CURRENT_USER_ID,
      receiver_id: OTHER_USER_ID,
      content: newMessage,
    };

    // Emit the message to the server
    socket.emit("sendMessage", messageData);

    // Add the message to our own state for an instant update
    setMessages((prevMessages) => [
      ...prevMessages,
      {
        sender_id: CURRENT_USER_ID,
        content: newMessage,
        created_at: new Date(),
      },
    ]);

    setNewMessage("");
  };

  return (
    <div className="app-container">
      <div className="chat-window">
        <header className="chat-header">
          <img
            src="data:image/jpeg;base64,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"
            alt="Avatar"
            className="avatar"
          />
          <div className="user-info">
            <h3>{OTHER_USER_NAME}</h3>
            <p>online</p> {/* Static for now */}
          </div>
        </header>

        <main className="message-list">
          {messages.map((msg, index) => {
            console.log(msg.sender_id);
            return (
              <div
                key={index}
                className={`message-bubble ${
                  msg.sender_id == CURRENT_USER_ID ? "sent" : "received"
                }`}
              >
                <p>{msg.content}</p>
                <span className="timestamp">
                  {new Date(msg.created_at).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </span>
              </div>
            );
          })}
          <div ref={messagesEndRef} />
        </main>

        <footer className="message-input">
          <form onSubmit={handleSendMessage}>
            <input
              type="text"
              placeholder="Type a message"
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
            />
            <button type="submit">
              <svg viewBox="0 0 24 24" width="24" height="24">
                <path
                  fill="currentColor"
                  d="M1.101 21.757L23.8 12.028 1.101 2.3l.011 7.912 13.623 1.816-13.623 1.817-.011 7.912z"
                ></path>
              </svg>
            </button>
          </form>
        </footer>
      </div>
    </div>
  );
}

export default App;


// import React from "react";
// import {
//   BrowserRouter,
//   Routes,
//   Route,
//   Navigate,
//   useNavigate
// } from "react-router-dom";
// import Login from "./pages/Login";
// import Signup from "./pages/Signup";
// import Home from "./pages/Home";

// function App() {
//   const token = localStorage.getItem("token");

//   return (
//     <BrowserRouter>
//       <Routes>
//         <Route
//           path="/login"
//           element={token ? <Navigate to="/" /> : <Login />}
//         />
//         <Route
//           path="/signup"
//           element={token ? <Navigate to="/" /> : <Signup />}
//         />

//         <Route path="/" element={token ? <Home /> : <Navigate to="/login" />} />

//         <Route path="*" element={<Navigate to={token ? "/" : "/login"} />} />
//       </Routes>
//     </BrowserRouter>
//   );
// }

// export default App;
