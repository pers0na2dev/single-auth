import type {
	BetterFetch,
	BetterFetchError,
	BetterFetchOption,
	BetterFetchPlugin,
	BetterFetchResponse,
} from "@better-fetch/fetch";
import type { Atom, StoreValue, WritableAtom } from "nanostores";

export type Prettify<T> = { [K in keyof T]: T[K] } & {};

export type PrettifyDeep<T> = {
	[K in keyof T]: T[K] extends (...args: any[]) => any
		? T[K]
		: T[K] extends readonly any[]
			? T[K]
			: T[K] extends Date
				? T[K]
				: T[K] extends object
					? PrettifyDeep<T[K]>
					: T[K];
} & {};

export type UnionToIntersection<U> = (
	U extends unknown ? (value: U) => void : never
) extends (value: infer I) => void
	? I
	: never;

export interface SingleAuthUser {
	id: string;
	name: string;
	email: string;
	emailVerified: boolean;
	image?: string | null | undefined;
	createdAt: Date;
	updatedAt: Date;
	[key: string]: unknown;
}

export interface SingleAuthSession {
	id: string;
	userId: string;
	expiresAt: Date;
	token: string;
	ipAddress?: string | null | undefined;
	userAgent?: string | null | undefined;
	createdAt: Date;
	updatedAt: Date;
	[key: string]: unknown;
}

export interface SingleAuthAccount {
	id: string;
	providerId: string;
	accountId: string;
	userId: string;
	scopes: string[];
	createdAt: Date;
	updatedAt: Date;
	[key: string]: unknown;
}

export interface ClientSchema<
	UserFields extends Record<string, unknown> = Record<never, never>,
	SessionFields extends Record<string, unknown> = Record<never, never>,
> {
	user?: UserFields | undefined;
	session?: SessionFields | undefined;
}

export type ClientFetchOption<
	Body = any,
	Query extends Record<string, any> = any,
	Params extends Record<string, any> | string[] | undefined = any,
	Response = any,
> = BetterFetchOption<Body, Query, Params, Response> & {
	disableSignal?: boolean | undefined;
};

export interface ClientStore {
	notify(signal?: string | undefined): void;
	listen(
		signal: string,
		listener: (value: unknown, oldValue?: unknown) => void,
	): () => void;
	atoms: Record<string, WritableAtom<any>>;
}

export interface ClientErrorCode<Code extends string = string> {
	readonly code: Code;
	readonly message: string;
	toString(): Code;
}

export interface ClientAtomListener {
	matcher(path: string): boolean;
	signal: string;
	callback?: ((path: string) => void) | undefined;
}

export interface BetterAuthClientPlugin<
	Actions extends Record<string, any> = Record<string, any>,
	Atoms extends Record<string, Atom<any>> = Record<string, Atom<any>>,
	ErrorCodes extends Record<string, ClientErrorCode> = Record<
		string,
		ClientErrorCode
	>,
> {
	id: string;
	version?: string | undefined;
	getActions?:
		| ((
				$fetch: BetterFetch,
				$store: ClientStore,
				options: BetterAuthClientOptions | undefined,
		  ) => Actions)
		| undefined;
	getAtoms?: (($fetch: BetterFetch) => Atoms) | undefined;
	pathMethods?: Record<string, "POST" | "GET"> | undefined;
	fetchPlugins?: BetterFetchPlugin[] | undefined;
	atomListeners?: ClientAtomListener[] | undefined;
	$ERROR_CODES?: ErrorCodes | undefined;
}

export interface SessionRevalidationOptions {
	/** Polling interval in seconds. Zero disables polling. */
	refetchInterval?: number | undefined;
	/** @default true */
	refetchOnWindowFocus?: boolean | undefined;
	/** @default false */
	refetchWhenOffline?: boolean | undefined;
}

export interface BetterAuthClientOptions<
	Plugins extends readonly BetterAuthClientPlugin[] = readonly BetterAuthClientPlugin[],
	Schema extends ClientSchema = ClientSchema,
> {
	fetchOptions?: ClientFetchOption | undefined;
	plugins?: Plugins | undefined;
	baseURL?: string | undefined;
	basePath?: string | undefined;
	disableDefaultFetchPlugins?: boolean | undefined;
	sessionOptions?: SessionRevalidationOptions | undefined;
	/**
	 * Single-auth-owned declaration hook for additional public user/session fields.
	 * It has no runtime effect and does not import a TypeScript auth server.
	 */
	schema?: Schema | undefined;
}

type InferSchema<O, Key extends "user" | "session"> = O extends {
	schema: infer Schema;
}
	? Schema extends Record<Key, infer Fields>
		? Fields extends Record<string, unknown>
			? Fields
			: Record<never, never>
		: Record<never, never>
	: Record<never, never>;

export type InferUser<O> = Prettify<SingleAuthUser & InferSchema<O, "user">>;
export type InferSession<O> = Prettify<
	SingleAuthSession & InferSchema<O, "session">
>;

export type SessionData<O = BetterAuthClientOptions> = {
	user: InferUser<O>;
	session: InferSession<O>;
	needsRefresh?: boolean | undefined;
} & Record<string, unknown>;

export interface SessionQueryParams {
	disableCookieCache?: boolean | undefined;
	disableRefresh?: boolean | undefined;
}

export interface AuthQueryState<T> {
	data: T | null;
	error: BetterFetchError | null;
	isPending: boolean;
	isRefetching: boolean;
	refetch(queryParams?: { query?: SessionQueryParams } | undefined): Promise<void>;
}

export type AuthQueryAtom<T> = WritableAtom<AuthQueryState<T>>;

export type InferActions<O> = O extends {
	plugins: readonly (infer Plugin)[];
}
	? UnionToIntersection<
			Plugin extends { getActions?: (...args: any[]) => infer Actions }
				? Actions
				: Record<never, never>
		>
	: Record<never, never>;

export type InferPluginAtoms<O> = O extends {
	plugins: readonly (infer Plugin)[];
}
	? UnionToIntersection<
			Plugin extends { getAtoms?: (...args: any[]) => infer Atoms }
				? Atoms
				: Record<never, never>
		>
	: Record<never, never>;

export type InferPluginErrorCodes<O> = O extends {
	plugins: readonly (infer Plugin)[];
}
	? UnionToIntersection<
			Plugin extends { $ERROR_CODES?: infer Codes }
				? Codes
				: Record<never, never>
		>
	: Record<never, never>;

export type IsSignal<Key> = Key extends `$${string}` ? true : false;

export type InferVanillaHooks<O> = {
	[Key in keyof InferPluginAtoms<O> as Key extends string
		? IsSignal<Key> extends true
			? never
			: `use${Capitalize<Key>}`
		: never]: InferPluginAtoms<O>[Key];
};

export type InferReactHooks<O> = {
	[Key in keyof InferPluginAtoms<O> as Key extends string
		? IsSignal<Key> extends true
			? never
			: `use${Capitalize<Key>}`
		: never]: InferPluginAtoms<O>[Key] extends Atom<any>
		? () => StoreValue<InferPluginAtoms<O>[Key]>
		: never;
};

export interface SingleAuthErrorBody {
	code?: string | undefined;
	message?: string | undefined;
	details?: unknown;
	[key: string]: unknown;
}

type CallThrows<O, F> = F extends { throw: true }
	? true
	: O extends { fetchOptions: { throw: true } }
		? true
		: false;

export type ClientResult<Data, O, F> = BetterFetchResponse<
	Data,
	SingleAuthErrorBody,
	CallThrows<O, F>
>;

type FetchOptionsCarrier<F extends ClientFetchOption = ClientFetchOption> = {
	fetchOptions?: F | undefined;
};

export type ClientEndpoint<Input, Output, O> = <
	F extends ClientFetchOption = ClientFetchOption,
>(
	input: Input & FetchOptionsCarrier<F>,
	fetchOptions?: F | undefined,
) => Promise<ClientResult<Output, O, F>>;

export type OptionalClientEndpoint<Input, Output, O> = <
	F extends ClientFetchOption = ClientFetchOption,
>(
	input?: (Input & FetchOptionsCarrier<F>) | undefined,
	fetchOptions?: F | undefined,
) => Promise<ClientResult<Output, O, F>>;

export type QueryClientEndpoint<
	Query,
	Output,
	O,
	Required extends boolean = false,
> = Required extends true
	? <F extends ClientFetchOption = ClientFetchOption>(
			input: { query: Query; fetchOptions?: F | undefined },
			fetchOptions?: F | undefined,
		) => Promise<ClientResult<Output, O, F>>
	: <F extends ClientFetchOption = ClientFetchOption>(
			input?: { query?: Query | undefined; fetchOptions?: F | undefined },
			fetchOptions?: F | undefined,
		) => Promise<ClientResult<Output, O, F>>;

export interface SignUpEmailInput {
	name: string;
	email: string;
	password: string;
	image?: string | undefined;
	callbackURL?: string | undefined;
	rememberMe?: boolean | undefined;
	[key: string]: unknown;
}

export interface SignInEmailInput {
	email: string;
	password: string;
	callbackURL?: string | undefined;
	rememberMe?: boolean | undefined;
}

interface BaseSocialIDTokenInput {
	token: string;
	accessToken?: string | undefined;
	refreshToken?: string | undefined;
	nonce?: string | undefined;
}

export interface SignInSocialIDTokenInput extends BaseSocialIDTokenInput {
	expiresAt?: number | undefined;
	user?: SignInSocialIDTokenUser | undefined;
}

export interface SignInSocialIDTokenUser {
	email?: string | undefined;
	name?:
		| {
				firstName?: string | undefined;
				lastName?: string | undefined;
		  }
		| undefined;
}

export interface LinkSocialIDTokenInput extends BaseSocialIDTokenInput {
	scopes?: string[] | undefined;
}

export interface SignInSocialInput {
	provider: string;
	callbackURL?: string | undefined;
	errorCallbackURL?: string | undefined;
	newUserCallbackURL?: string | undefined;
	disableRedirect?: boolean | undefined;
	requestSignUp?: boolean | undefined;
	scopes?: string[] | undefined;
	loginHint?: string | undefined;
	idToken?: SignInSocialIDTokenInput | undefined;
	additionalData?: Record<string, unknown> | undefined;
}

export interface LinkSocialInput {
	provider: string;
	callbackURL?: string | undefined;
	errorCallbackURL?: string | undefined;
	disableRedirect?: boolean | undefined;
	requestSignUp?: boolean | undefined;
	scopes?: string[] | undefined;
	idToken?: LinkSocialIDTokenInput | undefined;
	additionalData?: Record<string, unknown> | undefined;
}

export interface SignUpResponse<O> {
	token: string | null;
	user: InferUser<O>;
}

export interface SignInEmailResponse<O> {
	redirect: boolean;
	token: string;
	url?: string | undefined;
	user: InferUser<O>;
}

export interface SignInResponse<O> {
	redirect: boolean;
	token?: string | null | undefined;
	url?: string | null | undefined;
	user?: InferUser<O> | null | undefined;
}

export interface StatusResponse {
	status: boolean;
}

export interface StatusMessageResponse extends StatusResponse {
	message: string;
}

export interface SuccessMessageResponse {
	success: boolean;
	message: string;
}

export interface ChangePasswordInput {
	newPassword: string;
	currentPassword: string;
	revokeOtherSessions?: boolean | undefined;
}

export interface ChangePasswordResponse<O> {
	token: string | null;
	user: InferUser<O>;
}

export interface AccountTokenInput {
	providerId: string;
	accountId?: string | undefined;
}

export interface AccessTokenResponse {
	accessToken: string;
	accessTokenExpiresAt?: Date | null | undefined;
	scopes: string[];
	idToken?: string | undefined;
}

export interface RefreshTokenResponse {
	accessToken: string;
	refreshToken: string;
	accessTokenExpiresAt?: Date | null | undefined;
	refreshTokenExpiresAt?: Date | null | undefined;
	scope?: string | undefined;
	providerId: string;
	accountId: string;
	idToken?: string | undefined;
}

export interface ProviderUser {
	id: string;
	name: string;
	email?: string | null | undefined;
	image?: string | null | undefined;
	emailVerified: boolean;
	[key: string]: unknown;
}

export interface AccountInfoResponse {
	user: ProviderUser;
	data: unknown;
}

export interface ProxyRequest<F extends ClientFetchOption = ClientFetchOption> {
	query?: Record<string, unknown> | undefined;
	fetchOptions?: F | undefined;
	[key: string]: unknown;
}

type ThrowClientFetchOption = ClientFetchOption & { throw: true };
type NonOverridingClientFetchOption = ClientFetchOption & {
	throw?: undefined;
};

export interface DynamicClientCall<O> {
	<Output = unknown>(
		path: `/${string}`,
		input: ProxyRequest<ThrowClientFetchOption>,
		fetchOptions?: ClientFetchOption | undefined,
	): Promise<ClientResult<Output, O, ThrowClientFetchOption>>;
	<Output = unknown>(
		path: `/${string}`,
		input: ProxyRequest<NonOverridingClientFetchOption> | undefined,
		fetchOptions: ThrowClientFetchOption,
	): Promise<ClientResult<Output, O, ThrowClientFetchOption>>;
	<Output = unknown, F extends ClientFetchOption = ClientFetchOption>(
		path: `/${string}`,
		input?: ProxyRequest<F> | undefined,
		fetchOptions?: F | undefined,
	): Promise<ClientResult<Output, O, F>>;
}

export interface CoreAuthAPI<O = BetterAuthClientOptions> {
	signUp: {
		email: ClientEndpoint<SignUpEmailInput, SignUpResponse<O>, O>;
	};
	signIn: {
		email: ClientEndpoint<SignInEmailInput, SignInEmailResponse<O>, O>;
		social: ClientEndpoint<SignInSocialInput, SignInResponse<O>, O>;
	};
	signOut: OptionalClientEndpoint<Record<never, never>, { success: boolean }, O>;
	getSession: QueryClientEndpoint<SessionQueryParams, SessionData<O> | null, O>;
	updateUser: ClientEndpoint<
		Partial<Pick<InferUser<O>, "name" | "image">> & Record<string, unknown>,
		StatusResponse,
		O
	>;
	updateSession: ClientEndpoint<Record<string, unknown>, { session: InferSession<O> }, O>;
	changePassword: ClientEndpoint<ChangePasswordInput, ChangePasswordResponse<O>, O>;
	requestPasswordReset: ClientEndpoint<
		{ email: string; redirectTo?: string | undefined },
		StatusMessageResponse,
		O
	>;
	resetPassword: ClientEndpoint<
		{
			newPassword: string;
			token?: string | undefined;
			query?: { token?: string | undefined } | undefined;
		},
		StatusResponse,
		O
	>;
	verifyPassword: ClientEndpoint<{ password: string }, StatusResponse, O>;
	sendVerificationEmail: ClientEndpoint<
		{ email: string; callbackURL?: string | undefined },
		StatusResponse,
		O
	>;
	verifyEmail: QueryClientEndpoint<
		{ token: string; callbackURL?: string | undefined },
		{ status: boolean; user?: InferUser<O> | null | undefined },
		O,
		true
	>;
	changeEmail: ClientEndpoint<
		{ newEmail: string; callbackURL?: string | undefined },
		StatusResponse,
		O
	>;
	deleteUser: OptionalClientEndpoint<
		{ password?: string | undefined; token?: string | undefined; callbackURL?: string | undefined },
		SuccessMessageResponse,
		O
	>;
	listSessions: QueryClientEndpoint<Record<never, never>, InferSession<O>[], O>;
	revokeSession: ClientEndpoint<{ token: string }, StatusResponse, O>;
	revokeSessions: OptionalClientEndpoint<Record<never, never>, StatusResponse, O>;
	revokeOtherSessions: OptionalClientEndpoint<Record<never, never>, StatusResponse, O>;
	listAccounts: QueryClientEndpoint<Record<never, never>, SingleAuthAccount[], O>;
	unlinkAccount: ClientEndpoint<
		{ providerId: string; accountId?: string | undefined },
		StatusResponse,
		O
	>;
	linkSocial: ClientEndpoint<
		LinkSocialInput,
		{ url: string; status?: boolean | undefined; redirect: boolean },
		O
	>;
	getAccessToken: ClientEndpoint<AccountTokenInput, AccessTokenResponse, O>;
	refreshToken: ClientEndpoint<AccountTokenInput, RefreshTokenResponse, O>;
	accountInfo: QueryClientEndpoint<
		{ providerId?: string | undefined; accountId?: string | undefined },
		AccountInfoResponse | null,
		O
	>;
}
