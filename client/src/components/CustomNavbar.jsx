import React, { useState } from 'react';
import { Navbar, Container, Nav, Offcanvas, Button } from 'react-bootstrap';
import PropTypes from 'prop-types';

const CustomNavbar = ({ brand, links, user, handleLogout }) => {
    const [showSidebar, setShowSidebar] = useState(false);

    const handleCloseSidebar = () => setShowSidebar(false);
    const handleShowSidebar = () => setShowSidebar(true);

    return (
        <>
            {/* Top Navigation Bar */}
            <Navbar bg="dark" variant="dark" expand="lg" fixed="top" className="mb-3">
                <Container>
                    <Navbar.Brand href="/">{brand}</Navbar.Brand>
                    <Navbar.Toggle aria-controls="responsive-navbar-nav" onClick={handleShowSidebar} />
                    <Navbar.Collapse id="responsive-navbar-nav">
                        <Nav className="ms-auto">
                            {links.map((link, index) => (
                                <Nav.Link key={index} href={link.href}>
                                    {link.label}
                                </Nav.Link>
                            ))}
                            {/* Conditionally render the Logout button */}
                            {user ? (
                                <Button variant="outline-light" className="ms-2" onClick={handleLogout}>
                                    Logout
                                </Button>
                            ) : null}
                        </Nav>
                    </Navbar.Collapse>
                </Container>
            </Navbar>

            {/* Sidebar for Small Screens */}
            <Offcanvas show={showSidebar} onHide={handleCloseSidebar} placement="end">
                <Offcanvas.Header closeButton>
                    <Offcanvas.Title>Menu</Offcanvas.Title>
                </Offcanvas.Header>
                <Offcanvas.Body>
                    <Nav className="flex-column">
                        {links.map((link, index) => (
                            <Nav.Link key={index} href={link.href} onClick={handleCloseSidebar}>
                                {link.label}
                            </Nav.Link>
                        ))}
                        {/* Conditionally render the Logout button in the sidebar */}
                        {user ? (
                            <Button
                                variant="outline-dark"
                                className="mt-3"
                                onClick={() => {
                                    handleLogout();
                                    handleCloseSidebar();
                                }}
                            >
                                Logout
                            </Button>
                        ) : null}
                    </Nav>
                </Offcanvas.Body>
            </Offcanvas>
        </>
    );
};

CustomNavbar.propTypes = {
    brand: PropTypes.string.isRequired, // Brand name for the navbar
    links: PropTypes.arrayOf(
        PropTypes.shape({
            label: PropTypes.string.isRequired,
            href: PropTypes.string.isRequired,
        })
    ).isRequired,
    user: PropTypes.object,
    handleLogout: PropTypes.func,
};

export default CustomNavbar;
