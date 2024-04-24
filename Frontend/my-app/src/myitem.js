import React from 'react';




class Item extends React.Component{
    clickme(){
        alert("i was clicked")
    }
    
    render(){
      return(
        <div>
            <h1 onClick={()=>this.clickme()}>Welcome to React Learning with {this.props.name} & {this.props.Name}</h1>
            <h2 >Hello from Raunak Palewar</h2>
        </div>
      )
    }
  }

export default Item;