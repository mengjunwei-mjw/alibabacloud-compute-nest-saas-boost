import {
    SET_PROVIDER_NAME,
    SET_PROVIDER_OFFICIAL_LINK,
    SET_PROVIDER_DESCRIPTION,
} from './actions';

// 首先，定义State和Action的类型
interface State {
    providerName: string;
    providerOfficialLink: string;
    providerDescription: string;
}

interface Action {
    type: string;
    payload: any; // 或者更具体的类型，取决于你的payload
}

// initialState 明确为State类型
const initialState: State = {
    providerName: "服务商待填",
    providerOfficialLink: "服务商待填官网",
    providerDescription: "服务商待填描述信息",
};

export const providerInfoReducer = (state: State = initialState, action: Action): State => {
    switch (action.type) {
        case SET_PROVIDER_NAME:
            return {...state, providerName: action.payload};
        case SET_PROVIDER_OFFICIAL_LINK:
            return {...state, providerOfficialLink: action.payload};
        case SET_PROVIDER_DESCRIPTION:
            return {...state, providerDescription: action.payload};
        default:
            return state;
    }
};
