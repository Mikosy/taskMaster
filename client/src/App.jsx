// import { useState } from 'react'
// import reactLogo from './assets/react.svg'
// import viteLogo from '/vite.svg'
// import './App.css'
// import { Button, Alert, Breadcrumb, Card } from 'react-bootstrap'
// import 'bootstrap/dist/css/bootstrap.min.css'



import Signup from "./signup/Signup";
import './App.css';
import { RouterProvider, createBrowserRouter } from "react-router-dom";
import Login from "./login/Login";
import LandingPage from "./landingpage/landingPage";

function App() {
  const route = createBrowserRouter([
    {
      path: "/signup",
      element: <Signup />,
    },
    {
      path: "/login",
      element: <Login />,
    },
    {
      path: "/",
      element: <LandingPage />,
    },
  ]);
  return (
    <div className="App">
      <RouterProvider router={route}></RouterProvider>
    </div>
  );
}

export default App;
