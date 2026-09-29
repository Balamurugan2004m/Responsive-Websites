
import { render, screen } from "@testing-library/react";
import { renderHook } from "@testing-library/react";
import { AuthGuard, withAuth, useAuthGuard } from "./auth-guard";
import { useSelector } from "react-redux";
import { Navigate, useLocation } from "react-router";
import { JWTValidator } from "../../utils/jwt-validator";

/* ================= MOCKS ================= */

jest.mock("react-redux", () => ({
  useSelector: jest.fn(),
}));

jest.mock("react-router", () => ({
  Navigate: jest.fn(() => <div>Redirected</div>),
  useLocation: jest.fn(),
}));

jest.mock("../../utils/jwt-validator", () => ({
  JWTValidator: {
    isValidToken: jest.fn(),
    isTokenExpiringSoon: jest.fn(),
    hasAllRoles: jest.fn(),
    hasAnyRole: jest.fn(),
    getUserClaims: jest.fn(),
    hasClaim: jest.fn(),
    getUserFromToken: jest.fn(),
  },
}));

jest.mock("../../ui/loading-spinner", () => ({
  LoadingSpinner: ({ message }: any) => <div>{message}</div>,
}));

jest.mock("../../constants/paths", () => ({
  paths: {
    LOGIN: { pathName: "/login" },
    UNAUTHORIZED: { pathName: "/unauthorized" },
  },
}));

jest.mock("../../hooks/use-auth-rehydrated", () => ({
  useAuthRehydrated: jest.fn(() => true),
}));

/* ================= TYPE-SAFE MOCKS ================= */

// ✅ FIXED HERE
const mockUseSelector = useSelector as unknown as jest.Mock;
const mockUseLocation = useLocation as unknown as jest.Mock;
const mockNavigate = Navigate as unknown as jest.Mock;

/* ================= TESTS ================= */

describe("AuthGuard", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    const { useAuthRehydrated } = require("../../hooks/use-auth-rehydrated");
    (useAuthRehydrated as jest.Mock).mockReturnValue(true);
    mockUseLocation.mockReturnValue({ pathname: "/test" });
  });

  const renderComponent = (props: any = {}) =>
    render(
      <AuthGuard {...props}>
        <div>Protected</div>
      </AuthGuard>
    );

  it("shows loading while auth is rehydrating", () => {
    const { useAuthRehydrated } = require("../../hooks/use-auth-rehydrated");
    (useAuthRehydrated as jest.Mock).mockReturnValue(false);
    mockUseSelector.mockReturnValue({ authUser: {} });

    renderComponent();

    expect(screen.getByText("Loading session...")).toBeInTheDocument();
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it(" hides loading when showLoading false", () => {
    mockUseSelector.mockReturnValue({ authUser: { Token: "token" } });
    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);

    renderComponent({ showLoading: false });

    expect(screen.queryByText(/Validating authentication/i)).toBeNull();
  });

  it(" redirects when no token", () => {
    mockUseSelector.mockReturnValue({ authUser: {} });

    renderComponent();

    expect(mockNavigate).toHaveBeenCalled();
  });

  it("redirects when token invalid", () => {
    mockUseSelector.mockReturnValue({ authUser: { Token: "token" } });
    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(false);

    renderComponent();

    expect(mockNavigate).toHaveBeenCalled();
  });

  it("renders children when valid", () => {
    mockUseSelector.mockReturnValue({
      authUser: { Token: "token", UserTypeId: 1, Claims: [] },
    });

    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);

    renderComponent();

    expect(screen.getByText("Protected")).toBeInTheDocument();
  });

  it("redirects to unauthorized when user is a Veteran Portal user (UserTypeId: 4)", () => {
    mockUseSelector.mockReturnValue({
      authUser: { Token: "token", UserTypeId: 4, Claims: [] },
    });
    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);

    renderComponent();

    expect(mockNavigate).toHaveBeenCalledWith(
      expect.objectContaining({
        to: "/unauthorized",
        state: expect.objectContaining({
          isVeteranUser: true,
          reason: "vp_credentials",
        }),
      }),
      undefined
    );
  });

  it("role validation any fails", () => {
    mockUseSelector.mockReturnValue({ authUser: { Token: "token" } });
    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);
    (JWTValidator.hasAnyRole as jest.Mock).mockReturnValue(false);

    renderComponent({ requiredRoles: ["admin"] });

    expect(mockNavigate).toHaveBeenCalled();
  });

  it("role validation any passes", () => {
    mockUseSelector.mockReturnValue({ authUser: { Token: "token" } });
    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);
    (JWTValidator.hasAnyRole as jest.Mock).mockReturnValue(true);

    renderComponent({ requiredRoles: ["admin"] });

    expect(screen.getByText("Protected")).toBeInTheDocument();
  });

  it("role validation all fails", () => {
    mockUseSelector.mockReturnValue({ authUser: { Token: "token" } });
    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);
    (JWTValidator.hasAllRoles as jest.Mock).mockReturnValue(false);

    renderComponent({ requiredRoles: ["admin"], requireAllRoles: true });

    expect(mockNavigate).toHaveBeenCalled();
  });

  it("permission JSON fails", () => {
    mockUseSelector.mockReturnValue({ authUser: { Token: "token" } });

    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);
    (JWTValidator.getUserClaims as jest.Mock).mockReturnValue([
      { ClaimType: "permissions", ClaimValue: JSON.stringify(["read"]) },
    ]);

    renderComponent({ requiredPermissions: ["write"] });

    expect(mockNavigate).toHaveBeenCalled();
  });

  it(" permission JSON passes", () => {
    mockUseSelector.mockReturnValue({ authUser: { Token: "token" } });

    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);
    (JWTValidator.getUserClaims as jest.Mock).mockReturnValue([
      { ClaimType: "permissions", ClaimValue: JSON.stringify(["read"]) },
    ]);

    renderComponent({ requiredPermissions: ["read"] });

    expect(screen.getByText("Protected")).toBeInTheDocument();
  });

  it("permission parse fallback", () => {
    mockUseSelector.mockReturnValue({ authUser: { Token: "token" } });

    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);
    (JWTValidator.getUserClaims as jest.Mock).mockReturnValue([
      { ClaimType: "permissions", ClaimValue: "read" },
    ]);

    renderComponent({ requiredPermissions: ["read"] });

    expect(screen.getByText("Protected")).toBeInTheDocument();
  });

  it("permission fallback hasClaim", () => {
    mockUseSelector.mockReturnValue({ authUser: { Token: "token" } });

    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);
    (JWTValidator.getUserClaims as jest.Mock).mockReturnValue([]);
    (JWTValidator.hasClaim as jest.Mock).mockReturnValue(true);

    renderComponent({ requiredPermissions: ["read"] });

    expect(screen.getByText("Protected")).toBeInTheDocument();
  });

 
  it("claims single pass", () => {
    mockUseSelector.mockReturnValue({
      authUser: { Token: "token", Claims: [] },
    });

    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);
    (JWTValidator.hasClaim as jest.Mock).mockReturnValue(true);

    renderComponent({
      requiredClaims: [{ claimType: "dept", claimValue: "IT" }],
    });

    expect(screen.getByText("Protected")).toBeInTheDocument();
  });

  it("claims multiple any", () => {
    mockUseSelector.mockReturnValue({
      authUser: { Token: "token", Claims: [] },
    });

    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);
    (JWTValidator.hasClaim as jest.Mock).mockReturnValue(true);

    renderComponent({
      requiredClaims: [{ claimType: "role", claimValues: ["a", "b"] }],
    });

    expect(screen.getByText("Protected")).toBeInTheDocument();
  });


  it("fallback path used", () => {
    mockUseSelector.mockReturnValue({ authUser: {} });

    renderComponent({ fallbackPath: "/custom" });

    expect(mockNavigate).toHaveBeenCalled();
  });
});

/* ================= HOC ================= */

describe("withAuth", () => {
  it("wraps component", () => {
    const Comp = () => <div>Wrapped</div>;
    const Wrapped = withAuth(Comp);

    mockUseSelector.mockReturnValue({
      authUser: { Token: "token", Claims: [] },
    });

    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);

    render(<Wrapped />);

    expect(screen.getByText("Wrapped")).toBeInTheDocument();
  });
});

/* ================= HOOK ================= */

describe("useAuthGuard", () => {
  it("no token", () => {
    mockUseSelector.mockReturnValue({ authUser: {} });

    const { result } = renderHook(() => useAuthGuard());

    expect(result.current.canAccess).toBe(false);
  });

  it("valid token", () => {
    mockUseSelector.mockReturnValue({
      authUser: { Token: "token" },
    });

    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);

    const { result } = renderHook(() => useAuthGuard());

    expect(result.current.isAuthenticated).toBe(true);
  });

  it("role fails", () => {
    mockUseSelector.mockReturnValue({
      authUser: { Token: "token" },
    });

    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);
    (JWTValidator.hasAnyRole as jest.Mock).mockReturnValue(false);

    const { result } = renderHook(() =>
      useAuthGuard({ requiredRoles: ["admin"] })
    );

    expect(result.current.canAccess).toBe(false);
  });


  it("user extraction", () => {
    mockUseSelector.mockReturnValue({
      authUser: { Token: "token" },
    });

    (JWTValidator.isValidToken as jest.Mock).mockReturnValue(true);
    (JWTValidator.getUserFromToken as jest.Mock).mockReturnValue({
      name: "test",
    });

    const { result } = renderHook(() => useAuthGuard());

    expect(result.current.user).toEqual({ name: "test" });
  });
});
