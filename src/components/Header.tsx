import { useStytchB2BClient, useStytchMemberSession } from "@stytch/nextjs/b2b";
import Link from "next/link";
import { usePathname } from "next/navigation";
import "./Header.css";

const logoSrc = "/stytch.svg";

const Header = () => {
  const stytch = useStytchB2BClient();
  const { session } = useStytchMemberSession();

  const currentRoute = usePathname();
  const isOnDashboard = currentRoute === "/dashboard";

  const handleLogOut = () => {
    stytch.session.revoke();
  };

  return (
    <header className="header">
      <div className="logoContainer">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img loading="lazy" src={logoSrc} alt="Stytch logo" className="logo" />
        <div className="logoText">
          <Link href="/" className="customLink">
            Adaptive MFA (Example)
          </Link>
        </div>
      </div>
      <nav className="navLinks">
        <Link href="/" className="navLink">
          Docs
        </Link>
        <Link href="/" className="navLink">
          Github
        </Link>
        {session && isOnDashboard && (
          <button className="button" onClick={handleLogOut}>
            Logout
          </button>
        )}
      </nav>
    </header>
  );
};

export default Header;
