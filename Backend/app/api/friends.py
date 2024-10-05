from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.models import friend

router = APIRouter()

@router.post("/friends/request")
def send_friend_request(requester_id: int, receiver_ms_id: str, db: Session = Depends(get_db)):
    # Logic to send friend request by ms_id
    friend_request = friend.FriendRequest(requester_id=requester_id, receiver_id=receiver_ms_id)
    db.add(friend_request)
    db.commit()
    return {"msg": "Friend request sent"}

@router.post("/friends/accept")
def accept_friend_request(request_id: int, db: Session = Depends(get_db)):
    # Logic to accept friend request
    friend_request = db.query(friend.FriendRequest).filter(friend.FriendRequest.id == request_id).first()
    if not friend_request:
        raise HTTPException(status_code=400, detail="Friend request not found")
    friend_request.is_accepted = True
    db.commit()
    return {"msg": "Friend request accepted"}

@router.get("/friends/list")
def list_friends(user_id: int, db: Session = Depends(get_db)):
    # Logic to list friends
    friends = db.query(friend.FriendRequest).filter(friend.FriendRequest.requester_id == user_id).all()
    return {"friends": friends}
